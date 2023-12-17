#[cfg(test)]
mod merge_tests {
    use std::{fs::File, path::Path};
    use std::{thread, time};
    use uuid::Uuid;

    use crate::db::{Entry, Group, Node, Times};
    use crate::Database;

    fn get_entry_mut<'a>(db: &'a mut Database, path: &[&str]) -> &'a mut Entry {
        match db.root.get_mut(path).unwrap() {
            crate::db::NodeRefMut::Entry(e) => e,
            crate::db::NodeRefMut::Group(g) => panic!("An entry was expected."),
        }
    }

    fn get_group_mut<'a>(db: &'a mut Database, path: &[&str]) -> &'a mut Group {
        match db.root.get_mut(path).unwrap() {
            crate::db::NodeRefMut::Group(g) => g,
            crate::db::NodeRefMut::Entry(e) => panic!("A group was expected."),
        }
    }

    fn get_group<'a>(db: &'a mut Database, path: &[&str]) -> &'a Group {
        match db.root.get(path).unwrap() {
            crate::db::NodeRef::Group(g) => g,
            crate::db::NodeRef::Entry(e) => panic!("A group was expected."),
        }
    }

    fn get_all_groups(group: &Group) -> Vec<&Group> {
        let mut response: Vec<&Group> = vec![];
        for node in &group.children {
            match node {
                Node::Group(g) => {
                    let mut new_groups = get_all_groups(&g);
                    response.append(&mut new_groups);
                    response.push(&g);
                }
                _ => continue,
            }
        }
        response
    }

    fn get_all_entries(group: &Group) -> Vec<&Entry> {
        let mut response: Vec<&Entry> = vec![];
        for node in &group.children {
            match node {
                Node::Group(g) => {
                    let mut new_entries = get_all_entries(&g);
                    response.append(&mut new_entries);
                }
                Node::Entry(e) => {
                    response.push(&e);
                }
            }
        }
        response
    }

    const ROOT_GROUP_ID: &str = "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6a";
    const GROUP1_ID: &str = "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6b";
    const GROUP2_ID: &str = "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6c";
    const SUBGROUP1_ID: &str = "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d";
    const SUBGROUP2_ID: &str = "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6e";

    fn create_test_database() -> Database {
        let mut db = Database::new(Default::default());
        let mut root_group = Group::new("root");
        root_group.uuid = Uuid::parse_str(ROOT_GROUP_ID).unwrap();

        let mut group1 = Group::new("group1");
        group1.uuid = Uuid::parse_str(GROUP1_ID).unwrap();
        let mut group2 = Group::new("group2");
        group2.uuid = Uuid::parse_str(GROUP2_ID).unwrap();

        let mut subgroup1 = Group::new("subgroup1");
        subgroup1.uuid = Uuid::parse_str(SUBGROUP1_ID).unwrap();
        let mut subgroup2 = Group::new("subgroup2");
        subgroup2.uuid = Uuid::parse_str(SUBGROUP2_ID).unwrap();

        group1.add_child(subgroup1);
        group2.add_child(subgroup2);

        root_group.add_child(group1);
        root_group.add_child(group2);

        db.root = root_group;
        db
    }

    #[test]
    fn test_idempotence() {
        let mut destination_db = create_test_database();
        let mut entry = Entry::new();
        let entry_uuid = entry.uuid.clone();
        entry.set_field_and_commit("Title", "entry1");
        destination_db.root.add_child(entry);

        let mut source_db = destination_db.clone();

        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 0);
        assert_eq!(destination_db.root.children.len(), 3);
        // The 2 groups should be exactly the same after merging, since
        // nothing was performed during the merge.
        assert_eq!(destination_db, source_db);

        let mut entry = &mut destination_db.root.entries_mut()[0];
        entry.set_field_and_commit("Title", "entry1_updated");

        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 0);
        let destination_db_just_after_merge = destination_db.clone();

        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 0);
        // Merging twice in a row, even if the first merge updated the destination group,
        // should not create more changes.
        assert_eq!(destination_db_just_after_merge, destination_db);
    }

    #[test]
    fn test_add_new_entry() {
        let mut destination_db = create_test_database();

        let mut source_db = destination_db.clone();

        let mut entry = Entry::new();
        let entry_uuid = entry.uuid.clone();
        entry.set_field_and_commit("Title", "entry1");
        source_db.root.add_child(entry);

        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 1);
        assert_eq!(destination_db.root.children.len(), 3);

        let root_entries = destination_db.root.entries();
        assert_eq!(root_entries.len(), 1);
        let new_entry = root_entries.get(0);
        assert!(new_entry.is_some());
        assert_eq!(
            new_entry.unwrap().get_title().unwrap(),
            "entry1".to_string()
        );

        // Merging the same group again should not create a duplicate entry.
        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 0);
        assert_eq!(destination_db.root.children.len(), 3);
    }

    #[test]
    fn test_deleted_entry_in_destination() {
        let mut destination_db = create_test_database();

        let mut source_db = destination_db.clone();

        let mut entry = Entry::new();
        let entry_uuid = entry.uuid.clone();
        entry.set_field_and_commit("Title", "entry1");
        source_db.root.add_child(entry);

        destination_db
            .deleted_objects
            .objects
            .push(crate::db::DeletedObject {
                uuid: entry_uuid.clone(),
                deletion_time: Times::now(),
            });

        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 0);
        assert_eq!(destination_db.root.children.len(), 2);
        let new_entry = destination_db.root.find_node_location(entry_uuid);
        assert!(new_entry.is_none());
    }

    #[test]
    fn test_add_new_non_root_entry() {
        let mut destination_db = create_test_database();
        let mut source_db = destination_db.clone();

        let entry_count_before = get_all_entries(&destination_db.root).len();
        let group_count_before = get_all_groups(&destination_db.root).len();

        let mut source_sub_group = &mut source_db.root.groups_mut()[0];

        let mut entry = Entry::new();
        let entry_uuid = entry.uuid.clone();
        entry.set_field_and_commit("Title", "entry1");
        source_sub_group.add_child(entry);

        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 1);

        let entry_count_after = get_all_entries(&destination_db.root).len();
        let group_count_after = get_all_groups(&destination_db.root).len();
        assert_eq!(entry_count_after, entry_count_before + 1);
        assert_eq!(group_count_after, group_count_before);

        let created_entry_location = destination_db.root.find_node_location(entry_uuid).unwrap();
        assert_eq!(created_entry_location.len(), 2);
    }

    #[test]
    fn test_add_new_entry_new_group() {
        let mut destination_db = create_test_database();
        let mut source_db = destination_db.clone();

        let group_count_before = get_all_groups(&destination_db.root).len();
        let entry_count_before = get_all_entries(&destination_db.root).len();

        let mut source_group = Group::new("group2");
        let mut source_sub_group = Group::new("subgroup2");

        let mut entry = Entry::new();
        let entry_uuid = entry.uuid.clone();
        entry.set_field_and_commit("Title", "entry1");
        source_sub_group.add_child(entry);
        source_group.add_child(source_sub_group);
        source_db.root.add_child(source_group);

        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 3);

        let group_count_after = get_all_groups(&destination_db.root).len();
        let entry_count_after = get_all_entries(&destination_db.root).len();
        assert_eq!(entry_count_after, entry_count_before + 1);
        assert_eq!(group_count_after, group_count_before + 2);

        let created_entry_location = destination_db.root.find_node_location(entry_uuid).unwrap();
        assert_eq!(created_entry_location.len(), 3);
    }

    #[test]
    fn test_entry_relocation_existing_group() {
        let mut destination_db = create_test_database();

        let group_count_before = get_all_groups(&destination_db.root).len();
        let entry_count_before = get_all_entries(&destination_db.root).len();

        let mut entry = Entry::new();
        let entry_uuid = entry.uuid.clone();
        entry.set_field_and_commit("Title", "entry1");
        let mut destination_sub_group1 =
            get_group_mut(&mut destination_db, &["group1", "subgroup1"]);
        destination_sub_group1.add_child(entry.clone());

        let mut source_db = destination_db.clone();
        assert!(get_all_entries(&source_db.root).len() == 1);

        let mut relocated_entry = get_entry_mut(&mut source_db, &["group1", "subgroup1", "entry1"]);
        relocated_entry.times.set_location_changed(Times::now());
        // FIXME we should not have to update the history here. We should
        // have a better compare function in the merge function instead.
        relocated_entry.update_history();
        drop(&relocated_entry);

        source_db
            .relocate_node(
                &entry_uuid,
                &vec![
                    Uuid::parse_str(ROOT_GROUP_ID).unwrap(),
                    Uuid::parse_str(GROUP1_ID).unwrap(),
                    Uuid::parse_str(SUBGROUP1_ID).unwrap(),
                ],
                &vec![Uuid::parse_str(GROUP2_ID).unwrap()],
            )
            .unwrap();

        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 1);

        let group_count_after = get_all_groups(&destination_db.root).len();
        let entry_count_after = get_all_entries(&destination_db.root).len();
        assert_eq!(group_count_after, group_count_before);
        assert_eq!(entry_count_after, entry_count_before + 1);

        let moved_entry_location = destination_db.root.find_node_location(entry_uuid).unwrap();
        assert_eq!(moved_entry_location.len(), 2);
        assert_eq!(&moved_entry_location[0].to_string(), ROOT_GROUP_ID);
        assert_eq!(&moved_entry_location[1].to_string(), GROUP2_ID);
    }

    #[test]
    fn test_entry_relocation_new_group() {
        let mut destination_db = create_test_database();

        let entry_count_before = get_all_entries(&destination_db.root).len();
        let group_count_before = get_all_groups(&destination_db.root).len();

        let mut source_db = destination_db.clone();
        let mut new_group = Group::new("subgroup3");
        let new_group_uuid = new_group.uuid.clone();

        let mut entry = Entry::new();
        let entry_uuid = entry.uuid.clone();
        entry.set_field_and_commit("Title", "entry1");

        thread::sleep(time::Duration::from_secs(1));
        entry.times.set_location_changed(Times::now());
        // FIXME we should not have to update the history here. We should
        // have a better compare function in the merge function instead.
        entry.update_history();
        new_group.add_child(entry.clone());
        source_db.root.add_child(new_group);

        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 2);

        let entry_count_after = get_all_entries(&destination_db.root).len();
        let group_count_after = get_all_groups(&destination_db.root).len();
        assert_eq!(entry_count_after, entry_count_before + 1);
        assert_eq!(group_count_after, group_count_before + 1);

        let created_entry_location = destination_db.root.find_node_location(entry_uuid).unwrap();
        assert_eq!(created_entry_location.len(), 2);
        assert_eq!(&created_entry_location[0].to_string(), ROOT_GROUP_ID);
        assert_eq!(created_entry_location[1], new_group_uuid);
    }

    #[test]
    fn test_group_relocation() {
        let mut destination_db = create_test_database();

        let mut entry = Entry::new();
        let entry_uuid = entry.uuid.clone();
        entry.set_field_and_commit("Title", "entry1");

        let mut destination_sub_group1 =
            get_group_mut(&mut destination_db, &["group1", "subgroup1"]);
        destination_sub_group1.add_child(entry.clone());

        let entry_count_before = get_all_entries(&destination_db.root).len();
        let group_count_before = get_all_groups(&destination_db.root).len();

        let mut source_db = destination_db.clone();

        let mut source_group_1 = get_group_mut(&mut source_db, &["group1"]);
        let mut source_sub_group_1 = match source_group_1
            .remove_node(&Uuid::parse_str(SUBGROUP1_ID).unwrap())
            .unwrap()
        {
            Node::Group(g) => g,
            _ => panic!("This should not happen."),
        };
        thread::sleep(time::Duration::from_secs(1));
        source_sub_group_1.times.set_location_changed(Times::now());

        drop(source_group_1);
        let mut source_group_2 = get_group_mut(&mut source_db, &["group2"]);
        source_group_2.add_child(source_sub_group_1);

        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 1);

        let entry_count_after = get_all_entries(&destination_db.root).len();
        let group_count_after = get_all_groups(&destination_db.root).len();
        assert_eq!(entry_count_after, entry_count_before);
        assert_eq!(group_count_after, group_count_before);

        let created_entry_location = destination_db.root.find_node_location(entry_uuid).unwrap();
        assert_eq!(created_entry_location.len(), 3);
        assert_eq!(created_entry_location[0], destination_db.root.uuid);
        assert_eq!(&created_entry_location[1].to_string(), GROUP2_ID);
        assert_eq!(&created_entry_location[2].to_string(), SUBGROUP1_ID);
    }

    #[test]
    fn test_update_in_destination_no_conflict() {
        let mut destination_db = create_test_database();

        let mut entry = Entry::new();
        let entry_uuid = entry.uuid.clone();
        entry.set_field_and_commit("Title", "entry1");

        destination_db.root.add_child(entry);

        let mut source_db = destination_db.clone();

        let mut entry = &mut destination_db.root.entries_mut()[0];
        entry.set_field_and_commit("Title", "entry1_updated");

        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 0);

        let entry = destination_db.root.entries()[0];
        assert_eq!(entry.get_title(), Some("entry1_updated"));
    }

    #[test]
    fn test_update_in_source_no_conflict() {
        let mut destination_db = create_test_database();

        let mut entry = Entry::new();
        let entry_uuid = entry.uuid.clone();
        entry.set_field_and_commit("Title", "entry1");
        destination_db.root.add_child(entry);

        let mut source_db = destination_db.clone();

        let mut entry = &mut source_db.root.entries_mut()[0];
        entry.set_field_and_commit("Title", "entry1_updated");

        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 1);

        let entry = destination_db.root.entries()[0];
        assert_eq!(entry.get_title(), Some("entry1_updated"));
    }

    #[test]
    fn test_update_with_conflicts() {
        let mut destination_db = create_test_database();

        let mut entry = Entry::new();
        let entry_uuid = entry.uuid.clone();
        entry.set_field_and_commit("Title", "entry1");
        destination_db.root.add_child(entry);

        let mut source_db = destination_db.clone();

        let mut entry = &mut destination_db.root.entries_mut()[0];
        entry.set_field_and_commit("Title", "entry1_updated_from_destination");

        let mut entry = &mut source_db.root.entries_mut()[0];
        entry.set_field_and_commit("Title", "entry1_updated_from_source");

        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 1);

        let entry = destination_db.root.entries()[0];
        assert_eq!(entry.get_title(), Some("entry1_updated_from_source"));

        let merged_history = entry.history.clone().unwrap();
        assert!(merged_history.is_ordered());
        assert_eq!(merged_history.entries.len(), 3);
        let merged_entry = &merged_history.entries[1];
        assert_eq!(
            merged_entry.get_title(),
            Some("entry1_updated_from_destination")
        );

        // Merging again should not result in any additional change.
        let merge_result = destination_db.merge(&destination_db.clone()).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 0);
    }

    #[test]
    fn test_group_update_in_source() {
        let mut destination_db = create_test_database();

        let mut entry = Entry::new();
        let entry_uuid = entry.uuid.clone();
        entry.set_field_and_commit("Title", "entry1");
        destination_db.root.add_child(entry);

        let mut source_db = destination_db.clone();

        let mut group = get_group_mut(&mut source_db, &["group1", "subgroup1"]);
        group.name = "subgroup1_updated_name".to_string();
        // Making sure to wait 1 sec before update the timestamp, to make
        // sure that we get a different modification timestamp.
        thread::sleep(time::Duration::from_secs(1));
        let new_modification_timestamp = Times::now();
        group
            .times
            .set_last_modification(new_modification_timestamp);

        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 1);

        let mut modified_group =
            get_group(&mut destination_db, &["group1", "subgroup1_updated_name"]);
        assert_eq!(modified_group.name, "subgroup1_updated_name");
        assert_eq!(
            modified_group.times.get_last_modification(),
            Some(new_modification_timestamp).as_ref(),
        );
    }

    #[test]
    fn test_group_update_in_destination() {
        let mut destination_db = create_test_database();

        let mut entry = Entry::new();
        let entry_uuid = entry.uuid.clone();
        entry.set_field_and_commit("Title", "entry1");
        destination_db.root.add_child(entry);

        let mut source_db = destination_db.clone();

        let mut group = get_group_mut(&mut destination_db, &["group1", "subgroup1"]);
        group.name = "subgroup1_updated_name".to_string();
        // Making sure to wait 1 sec before update the timestamp, to make
        // sure that we get a different modification timestamp.
        thread::sleep(time::Duration::from_secs(1));
        let new_modification_timestamp = Times::now();
        group
            .times
            .set_last_modification(new_modification_timestamp);

        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 0);

        let mut modified_group =
            get_group(&mut destination_db, &["group1", "subgroup1_updated_name"]);
        assert_eq!(modified_group.name, "subgroup1_updated_name");
        assert_eq!(
            modified_group.times.get_last_modification(),
            Some(new_modification_timestamp).as_ref(),
        );
    }

    #[test]
    fn test_group_update_and_relocation() {
        let mut destination_db = create_test_database();

        let mut entry = Entry::new();
        let entry_uuid = entry.uuid.clone();
        entry.set_field_and_commit("Title", "entry1");
        destination_db.root.add_child(entry);

        let mut source_db = destination_db.clone();

        let mut group = get_group_mut(&mut source_db, &["group1", "subgroup1"]);
        group.name = "subgroup1_updated_name".to_string();
        // Making sure to wait 1 sec before update the timestamp, to make
        // sure that we get a different modification timestamp.
        thread::sleep(time::Duration::from_secs(1));
        let new_modification_timestamp = Times::now();
        group
            .times
            .set_last_modification(new_modification_timestamp);
        group.times.set_location_changed(new_modification_timestamp);

        source_db
            .relocate_node(
                &Uuid::parse_str(SUBGROUP1_ID).unwrap(),
                &vec![
                    Uuid::parse_str(ROOT_GROUP_ID).unwrap(),
                    Uuid::parse_str(GROUP1_ID).unwrap(),
                ],
                &vec![Uuid::parse_str(GROUP2_ID).unwrap()],
            )
            .unwrap();

        let merge_result = destination_db.merge(&source_db).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 2);

        let mut modified_group =
            get_group(&mut destination_db, &["group2", "subgroup1_updated_name"]);
        assert_eq!(modified_group.name, "subgroup1_updated_name");
        assert_eq!(
            modified_group.times.get_last_modification(),
            Some(new_modification_timestamp).as_ref(),
        );
    }
}
