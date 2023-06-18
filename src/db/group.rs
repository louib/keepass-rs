use std::collections::VecDeque;

use uuid::Uuid;

use crate::db::{
    entry::{Entry, Value},
    node::{Node, NodeIter, NodeRef, NodeRefMut},
    CustomData, Times,
};

#[derive(Debug, Clone)]
pub enum MergeEventType {
    EntryCreated,
    EntryLocationUpdated,

    EntryUpdated,
    GroupCreated,
}

#[derive(Debug, Clone)]
pub struct MergeEvent {
    /// The uuid of the node (entry or group) affected by
    /// the merge event.
    pub node_uuid: Uuid,

    pub event_type: MergeEventType,
}

#[derive(Debug, Default, Clone)]
pub struct MergeLog {
    pub warnings: Vec<String>,
    pub events: Vec<MergeEvent>,
}

impl MergeLog {
    pub fn merge_with(&self, other: &MergeLog) -> MergeLog {
        let mut response = MergeLog::default();
        response.warnings.append(self.warnings.clone().as_mut());
        response.warnings.append(other.warnings.clone().as_mut());
        response.events.append(self.events.clone().as_mut());
        response.events.append(other.events.clone().as_mut());
        response
    }
}

#[derive(Debug, Default, Eq, PartialEq, Clone)]
pub(crate) struct GroupRef {
    pub uuid: Uuid,
    pub name: String,
}

pub(crate) type NodeLocation = Vec<GroupRef>;

/// A database group with child groups and entries
#[derive(Debug, Default, Eq, PartialEq, Clone)]
#[cfg_attr(feature = "serialization", derive(serde::Serialize))]
pub struct Group {
    /// The unique identifier of the group
    pub uuid: Uuid,

    /// The name of the group
    pub name: String,

    /// Notes for the group
    pub notes: Option<String>,

    /// ID of the group's icon
    pub icon_id: Option<usize>,

    /// UUID for a custom group icon
    pub custom_icon_uuid: Option<Uuid>,

    /// The list of child nodes (Groups or Entries)
    pub children: Vec<Node>,

    /// The list of time fields for this group
    pub times: Times,

    // Custom Data
    pub custom_data: CustomData,

    /// Whether the group is expanded in the user interface
    pub is_expanded: bool,

    /// Default autotype sequence
    pub default_autotype_sequence: Option<String>,

    /// Whether autotype is enabled
    // TODO: in example XML files, this is "null" - what should the type be?
    pub enable_autotype: Option<String>,

    /// Whether searching is enabled
    // TODO: in example XML files, this is "null" - what should the type be?
    pub enable_searching: Option<String>,

    /// UUID for the last top visible entry
    // TODO figure out what that is supposed to mean. According to the KeePass sourcecode, it has
    // something to do with restoring selected items when re-opening a database.
    pub last_top_visible_entry: Option<Uuid>,
}

impl Group {
    pub fn new(name: &str) -> Group {
        Group {
            name: name.to_string(),
            times: Times::new(),
            uuid: Uuid::new_v4(),
            ..Default::default()
        }
    }

    /// Recursively get a Group or Entry reference by specifying a path relative to the current Group
    /// ```
    /// use keepass::{Database, DatabaseKey, db::NodeRef};
    /// use std::{fs::File, path::Path};
    ///
    /// let path = Path::new("tests/resources/test_db_with_password.kdbx");
    /// let db = Database::open(
    ///     &mut File::open(path).unwrap(),
    ///     DatabaseKey::with_password("demopass")
    /// ).unwrap();
    ///
    /// if let Some(NodeRef::Entry(e)) = db.root.get(&["General", "Sample Entry #2"]) {
    ///     println!("User: {}", e.get_username().unwrap());
    /// }
    /// ```
    pub fn get<'a>(&'a self, path: &[&str]) -> Option<NodeRef<'a>> {
        if path.is_empty() {
            Some(NodeRef::Group(self))
        } else {
            if path.len() == 1 {
                let head = path[0];
                self.children.iter().find_map(|n| match n {
                    Node::Group(_) => None,
                    Node::Entry(e) => {
                        e.get_title()
                            .and_then(|t| if t == head { Some(n.as_ref()) } else { None })
                    }
                })
            } else {
                let head = path[0];
                let tail = &path[1..path.len()];

                let head_group = self.children.iter().find_map(|n| match n {
                    Node::Group(g) if g.name == head => Some(g),
                    _ => None,
                })?;

                head_group.get(tail)
            }
        }
    }

    /// Recursively get a mutable reference to a Group or Entry by specifying a path relative to
    /// the current Group
    pub fn get_mut<'a>(&'a mut self, path: &[&str]) -> Option<NodeRefMut<'a>> {
        if path.is_empty() {
            Some(NodeRefMut::Group(self))
        } else {
            if path.len() == 1 {
                let head = path[0];
                self.children
                    .iter_mut()
                    .filter(|n| match n {
                        Node::Group(g) => g.name == head,
                        Node::Entry(e) => e.get_title().map(|t| t == head).unwrap_or(false),
                    })
                    .map(|t| t.as_mut())
                    .next()
            } else {
                let head = path[0];
                let tail = &path[1..path.len()];

                let head_group: &mut Group = self.children.iter_mut().find_map(|n| match n {
                    Node::Group(g) if g.name == head => Some(g),
                    _ => None,
                })?;

                head_group.get_mut(tail)
            }
        }
    }

    /// Get a timestamp field by name
    ///
    /// Returning the chrono::NaiveDateTime which does not include timezone
    /// or UTC offset because KeePass clients typically store timestamps
    /// relative to the local time on the machine writing the data without
    /// including accurate UTC offset or timezone information.
    pub fn get_time(&self, key: &str) -> Option<&chrono::NaiveDateTime> {
        self.times.get(key)
    }

    /// Convenience method for getting the time that the group expires
    pub fn get_expiry_time(&self) -> Option<&chrono::NaiveDateTime> {
        self.times.get_expiry()
    }

    pub fn entries(&self) -> Vec<&Entry> {
        let mut response: Vec<&Entry> = vec![];
        for node in &self.children {
            if let Node::Entry(e) = node {
                response.push(e)
            }
        }
        response
    }

    pub fn entries_mut(&mut self) -> Vec<&mut Entry> {
        let mut response: Vec<&mut Entry> = vec![];
        for node in &mut self.children {
            if let Node::Entry(e) = node {
                response.push(e)
            }
        }
        response
    }

    pub fn groups_mut(&mut self) -> Vec<&mut Group> {
        let mut response: Vec<&mut Group> = vec![];
        for node in &mut self.children {
            if let Node::Group(g) = node {
                response.push(g);
            }
        }
        response
    }

    fn replace_entry(&mut self, entry: &Entry) {
        for node in &mut self.children {
            match node {
                Node::Group(g) => {
                    g.replace_entry(entry);
                }
                Node::Entry(e) => {
                    if e.uuid == entry.uuid {
                        *e = entry.clone();
                    }
                }
            }
        }
    }

    pub(crate) fn has_group(&self, uuid: Uuid) -> bool {
        for node in &self.children {
            if let Node::Group(g) = node {
                if g.uuid == uuid {
                    return true;
                }
            }
        }
        false
    }

    pub(crate) fn get_group_mut(
        &mut self,
        location: &NodeLocation,
        create_groups: bool,
    ) -> Result<&mut Group, String> {
        if location.len() == 0 {
            return Err("Empty location.".to_string());
        }

        let mut remaining_location = location.clone();
        remaining_location.remove(0);

        if remaining_location.len() == 0 {
            return Ok(self);
        }

        let next_location = &remaining_location[0];
        let mut next_location_uuid = next_location.uuid;

        if !self.has_group(next_location_uuid) && create_groups {
            let mut current_group: Option<Group> = None;
            for i in (0..(remaining_location.len())).rev() {
                let mut new_group = Group::new(&remaining_location[i].name);
                if let Some(group) = &current_group {
                    new_group.add_node(group.clone());
                }
                current_group = Some(new_group);
            }

            let current_group = current_group.unwrap();
            next_location_uuid = current_group.uuid;
            self.add_node(current_group);
        }

        for node in &mut self.children {
            if let Node::Group(g) = node {
                if g.uuid != next_location_uuid {
                    continue;
                }
                return g.get_group_mut(&remaining_location, create_groups);
            }
        }

        return Err("The group was not found.".to_string());
    }

    pub fn add_node<T>(&mut self, n: T)
    where
        T: Into<Node>,
    {
        self.children.push(n.into())
    }

    pub(crate) fn insert_entry(
        &mut self,
        entry: Entry,
        location: &NodeLocation,
    ) -> Result<(), String> {
        let mut group: &mut Group = self.get_group_mut(&location, true)?;
        group.children.push(Node::Entry(entry));
        Ok(())
    }

    pub(crate) fn remove_entry(
        &mut self,
        uuid: &Uuid,
        location: &NodeLocation,
    ) -> Result<Entry, String> {
        let mut group: &mut Group = self.get_group_mut(&location, false)?;

        let mut removed_entry: Option<Entry> = None;
        let mut new_nodes: Vec<Node> = vec![];
        println!("Searching for entry {} in {}", uuid, group.name);
        for node in &group.children {
            match node {
                Node::Entry(e) => {
                    println!("Saw entry {}", &e.uuid);
                    if &e.uuid != uuid {
                        new_nodes.push(node.clone());
                        continue;
                    }
                    removed_entry = Some(e.clone());
                }
                Node::Group(_) => {
                    new_nodes.push(node.clone());
                }
            }
        }

        if let Some(entry) = removed_entry {
            group.children = new_nodes;
            return Ok(entry);
        } else {
            return Err(format!(
                "Could not find entry {} in group {}.",
                uuid, group.name
            ));
        }
    }

    pub(crate) fn find_entry_location(&self, id: Uuid) -> Option<NodeLocation> {
        let mut current_location = vec![GroupRef {
            uuid: self.uuid.clone(),
            name: self.name.clone(),
        }];
        for node in &self.children {
            match node {
                Node::Entry(e) => {
                    if e.uuid == id {
                        return Some(current_location);
                    }
                }
                Node::Group(g) => {
                    if let Some(mut location) = g.find_entry_location(id) {
                        current_location.append(&mut location);
                        return Some(current_location);
                    }
                }
            }
        }
        None
    }

    pub fn find_entry_by_uuid(&self, id: Uuid) -> Option<&Entry> {
        for node in &self.children {
            match node {
                Node::Group(g) => {
                    if let Some(e) = g.find_entry_by_uuid(id) {
                        return Some(e);
                    }
                }
                Node::Entry(e) => {
                    if e.uuid == id {
                        return Some(e);
                    }
                }
            }
        }
        None
    }

    pub(crate) fn add_entry(&mut self, entry: Entry, location: &NodeLocation) {
        if location.len() == 0 {
            panic!("TODO handle this with a Response.");
        }

        let mut remaining_location = location.clone();
        remaining_location.remove(0);

        if remaining_location.len() == 0 {
            self.children.push(Node::Entry(entry.clone()));
            return;
        }

        let next_location = &remaining_location[0];

        println!(
            "Searching for group {} {:?}",
            next_location.name, next_location.uuid
        );
        for node in &mut self.children {
            if let Node::Group(g) = node {
                if g.uuid != next_location.uuid {
                    continue;
                }
                g.add_entry(entry, &remaining_location);
                return;
            }
        }

        // The group was not found, so we create it.
        let mut new_group = Group {
            name: next_location.name.clone(),
            uuid: next_location.uuid.clone(),
            ..Default::default()
        };
        new_group.add_entry(entry, &remaining_location);
        self.children.push(Node::Group(new_group));
    }

    /// Merge this group with another group
    pub fn merge(&mut self, other: &Group) -> Result<MergeLog, String> {
        let mut log = MergeLog::default();

        // Handle entry relocation.
        for (entry, entry_location) in other.get_all_entries(&vec![]) {
            let existing_entry = match self.find_entry_by_uuid(entry.uuid) {
                Some(e) => e,
                None => continue,
            };
            let existing_entry_location = match self.find_entry_location(entry.uuid) {
                Some(l) => l,
                None => continue,
            };

            let source_location_changed_time = match entry.times.get_location_changed() {
                Some(t) => *t,
                None => {
                    log.warnings.push(format!(
                        "Entry {} did not have a location updated timestamp",
                        entry.uuid
                    ));
                    Times::epoch()
                }
            };
            let destination_location_changed = match existing_entry.times.get_location_changed() {
                Some(t) => *t,
                None => {
                    log.warnings.push(format!(
                        "Entry {} did not have a location updated timestamp",
                        entry.uuid
                    ));
                    Times::now()
                }
            };
            if source_location_changed_time > destination_location_changed {
                log.events.push(MergeEvent {
                    event_type: MergeEventType::EntryLocationUpdated,
                    node_uuid: entry.uuid,
                });
                let removed_entry = self.remove_entry(&entry.uuid, &existing_entry_location)?;
                self.insert_entry(entry.clone(), &entry_location)?;
            }
        }

        // Handle entry updates
        for (entry, entry_location) in other.get_all_entries(&vec![]) {
            if let Some(existing_entry) = self.find_entry_by_uuid(entry.uuid) {
                if existing_entry == entry {
                    continue;
                }

                let source_last_modification = match entry.times.get_last_modification() {
                    Some(t) => *t,
                    None => {
                        log.warnings.push(format!(
                            "Entry {} did not have a last modification timestamp",
                            entry.uuid
                        ));
                        Times::epoch()
                    }
                };
                let destination_last_modification =
                    match existing_entry.times.get_last_modification() {
                        Some(t) => *t,
                        None => {
                            log.warnings.push(format!(
                                "Entry {} did not have a last modification timestamp",
                                entry.uuid
                            ));
                            Times::now()
                        }
                    };

                if destination_last_modification == source_last_modification {
                    println!(
                        "{:?} == {:?}",
                        destination_last_modification, source_last_modification
                    );
                    continue;
                }

                let (merged_entry, entry_merge_log) = existing_entry.merge(entry)?;
                self.replace_entry(&merged_entry);
                log.events.push(MergeEvent {
                    event_type: MergeEventType::EntryUpdated,
                    node_uuid: merged_entry.uuid,
                });
                log = log.merge_with(&entry_merge_log);
            } else {
                self.add_entry(entry.clone(), &entry_location);
                // TODO should we update the time info for the entry?
                log.events.push(MergeEvent {
                    event_type: MergeEventType::EntryCreated,
                    node_uuid: entry.uuid,
                });
            }
        }

        // TODO handle deleted objects
        Ok(log)
    }

    // Recursively get all the entries in the group, along with their
    // location.
    pub(crate) fn get_all_entries(
        &self,
        current_location: &NodeLocation,
    ) -> Vec<(&Entry, NodeLocation)> {
        let mut response: Vec<(&Entry, NodeLocation)> = vec![];
        let mut new_location = current_location.clone();
        new_location.push(GroupRef {
            uuid: self.uuid.clone(),
            name: self.name.clone(),
        });

        for node in &self.children {
            match node {
                Node::Entry(e) => {
                    response.push((&e, new_location.clone()));
                }
                Node::Group(g) => {
                    let mut new_entries = g.get_all_entries(&new_location);
                    response.append(&mut new_entries);
                }
            }
        }
        response
    }
}

impl<'a> Group {
    pub fn iter(&'a self) -> NodeIter<'a> {
        (&self).into_iter()
    }
}

impl<'a> IntoIterator for &'a Group {
    type Item = NodeRef<'a>;
    type IntoIter = NodeIter<'a>;

    fn into_iter(self) -> NodeIter<'a> {
        let mut queue: VecDeque<NodeRef> = VecDeque::new();
        queue.push_back(NodeRef::Group(self));

        NodeIter::new(queue)
    }
}

#[cfg(test)]
mod group_tests {
    use std::{thread, time};

    use super::{Entry, Group, GroupRef, Node, Times, Value};

    #[test]
    fn test_merge_idempotence() {
        let mut destination_group = Group::new("group1");
        let mut entry = Entry::new();
        let entry_uuid = entry.uuid.clone();
        entry.set_field_and_commit("Title", "entry1");
        destination_group.add_node(entry);

        let mut source_group = destination_group.clone();

        let merge_result = destination_group.merge(&source_group).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 0);
        assert_eq!(destination_group.children.len(), 1);
        // The 2 groups should be exactly the same after merging, since
        // nothing was performed during the merge.
        assert_eq!(destination_group, source_group);

        let mut entry = &mut destination_group.entries_mut()[0];
        entry.set_field_and_commit("Title", "entry1_updated");

        let merge_result = destination_group.merge(&source_group).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 1);
        let destination_group_just_after_merge = destination_group.clone();

        let merge_result = destination_group.merge(&source_group).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        // FIXME we should detect if merging the entries actually changed something,
        // and not add an event if nothing changed.
        // assert_eq!(merge_result.events.len(), 0);
        // Merging twice in a row, even if the first merge updated the destination group,
        // should not create more changes.
        assert_eq!(destination_group_just_after_merge, destination_group);
    }

    #[test]
    fn test_merge_add_new_entry() {
        let mut destination_group = Group::new("group1");
        let mut source_group = Group::new("group1");

        let mut entry = Entry::new();
        let entry_uuid = entry.uuid.clone();
        entry.set_field_and_commit("Title", "entry1");
        source_group.add_node(entry);

        destination_group.merge(&source_group).unwrap();
        assert_eq!(destination_group.children.len(), 1);
        let new_entry = destination_group.find_entry_by_uuid(entry_uuid);
        assert!(new_entry.is_some());
        assert_eq!(
            new_entry.unwrap().get_title().unwrap(),
            "entry1".to_string()
        );

        // Merging the same group again should not create a duplicate entry.
        let merge_result = destination_group.merge(&source_group).unwrap();
        assert_eq!(merge_result.events.len(), 0);
        assert_eq!(destination_group.children.len(), 1);
    }

    #[test]
    fn test_merge_add_new_non_root_entry() {
        let mut destination_group = Group::new("group1");
        let mut destination_sub_group = Group::new("subgroup1");
        destination_group.add_node(destination_sub_group);

        let mut source_group = destination_group.clone();
        let mut source_sub_group = &mut source_group.groups_mut()[0];

        let mut entry = Entry::new();
        let entry_uuid = entry.uuid.clone();
        entry.set_field_and_commit("Title", "entry1");
        source_sub_group.add_node(entry);

        destination_group.merge(&source_group).unwrap();
        let destination_entries = destination_group.get_all_entries(&vec![]);
        assert_eq!(destination_entries.len(), 1);
        let (created_entry, created_entry_location) = destination_entries.get(0).unwrap();
        println!("{:?}", created_entry_location);
        assert_eq!(created_entry_location.len(), 2);
    }

    #[test]
    fn test_merge_add_new_entry_new_group() {
        let mut destination_group = Group::new("group1");
        let mut destination_sub_group = Group::new("subgroup1");
        let mut source_group = Group::new("group1");
        let mut source_sub_group = Group::new("subgroup1");

        let mut entry = Entry::new();
        let entry_uuid = entry.uuid.clone();
        entry.set_field_and_commit("Title", "entry1");
        source_sub_group.add_node(entry);
        source_group.add_node(source_sub_group);

        destination_group.merge(&source_group).unwrap();
        let destination_entries = destination_group.get_all_entries(&vec![]);
        assert_eq!(destination_entries.len(), 1);
        let (created_entry, created_entry_location) = destination_entries.get(0).unwrap();
        assert_eq!(created_entry_location.len(), 2);
    }

    #[test]
    fn test_merge_entry_relocation_existing_group() {
        let mut entry = Entry::new();
        let entry_uuid = entry.uuid.clone();
        entry.set_field_and_commit("Title", "entry1");
        let mut destination_group = Group::new("group1");
        let mut destination_sub_group1 = Group::new("subgroup1");
        let mut destination_sub_group2 = Group::new("subgroup2");
        destination_sub_group1.add_node(entry.clone());
        destination_group.add_node(destination_sub_group1.clone());
        destination_group.add_node(destination_sub_group2.clone());

        let mut source_group = destination_group.clone();
        assert!(source_group.get_all_entries(&vec![]).len() == 1);

        let mut removed_entry = source_group
            .remove_entry(
                &entry_uuid,
                &vec![
                    GroupRef {
                        uuid: destination_group.uuid.clone(),
                        name: "".to_string(),
                    },
                    GroupRef {
                        uuid: destination_sub_group1.uuid.clone(),
                        name: "".to_string(),
                    },
                ],
            )
            .unwrap();
        removed_entry.times.set_location_changed(Times::now());
        assert!(source_group.get_all_entries(&vec![]).len() == 0);
        // FIXME we should not have to update the history here. We should
        // have a better compare function in the merge function instead.
        removed_entry.update_history();
        source_group
            .insert_entry(
                removed_entry,
                &vec![
                    GroupRef {
                        uuid: destination_group.uuid.clone(),
                        name: "".to_string(),
                    },
                    GroupRef {
                        uuid: destination_sub_group2.uuid.clone(),
                        name: "".to_string(),
                    },
                ],
            )
            .unwrap();

        destination_group.merge(&source_group).unwrap();

        let destination_entries = destination_group.get_all_entries(&vec![]);
        assert_eq!(destination_entries.len(), 1);
        let (moved_entry, moved_entry_location) = destination_entries.get(0).unwrap();
        assert_eq!(moved_entry_location.len(), 2);
        assert_eq!(moved_entry_location[0].name, "group1".to_string());
        assert_eq!(moved_entry_location[1].name, "subgroup2".to_string());
    }

    #[test]
    fn test_merge_entry_relocation_new_group() {
        let mut entry = Entry::new();
        let entry_uuid = entry.uuid.clone();
        entry.set_field_and_commit("Title", "entry1");

        let mut destination_group = Group::new("group1");
        let mut destination_sub_group = Group::new("subgroup1");
        destination_sub_group.add_node(entry.clone());
        destination_group.add_node(destination_sub_group);

        let mut source_group = destination_group.clone();
        let mut source_sub_group = Group::new("subgroup2");
        thread::sleep(time::Duration::from_secs(1));
        entry.times.set_location_changed(Times::now());
        // FIXME we should not have to update the history here. We should
        // have a better compare function in the merge function instead.
        entry.update_history();
        source_sub_group.add_node(entry.clone());
        source_group.children = vec![];
        source_group.add_node(source_sub_group);

        let merge_result = destination_group.merge(&source_group).unwrap();
        println!("{:?}", merge_result.events);
        assert_eq!(merge_result.events.len(), 1);

        let destination_entries = destination_group.get_all_entries(&vec![]);
        assert_eq!(destination_entries.len(), 1);
        let (created_entry, created_entry_location) = destination_entries.get(0).unwrap();
        assert_eq!(created_entry_location.len(), 2);
        assert_eq!(created_entry_location[0].name, "group1".to_string());
        assert_eq!(created_entry_location[1].name, "subgroup2".to_string());
    }

    #[test]
    fn test_update_in_destination_no_conflict() {
        let mut destination_group = Group::new("group1");

        let mut entry = Entry::new();
        let entry_uuid = entry.uuid.clone();
        entry.set_field_and_commit("Title", "entry1");

        destination_group.add_node(entry);

        let mut source_group = destination_group.clone();

        let mut entry = &mut destination_group.entries_mut()[0];
        entry.set_field_and_commit("Title", "entry1_updated");

        destination_group.merge(&source_group).unwrap();

        let entry = destination_group.entries()[0];
        assert_eq!(entry.get_title(), Some("entry1_updated"));
    }

    #[test]
    fn test_update_in_source_no_conflict() {
        let mut destination_group = Group::new("group1");

        let mut entry = Entry::new();
        let entry_uuid = entry.uuid.clone();
        entry.set_field_and_commit("Title", "entry1");
        destination_group.add_node(entry);

        let mut source_group = destination_group.clone();

        let mut entry = &mut source_group.entries_mut()[0];
        entry.set_field_and_commit("Title", "entry1_updated");

        destination_group.merge(&source_group).unwrap();

        let entry = destination_group.entries()[0];
        assert_eq!(entry.get_title(), Some("entry1_updated"));
    }

    #[test]
    fn test_update_with_conflicts() {
        let mut destination_group = Group::new("group1");

        let mut entry = Entry::new();
        let entry_uuid = entry.uuid.clone();
        entry.set_field_and_commit("Title", "entry1");
        destination_group.add_node(entry);

        let mut source_group = destination_group.clone();

        let mut entry = &mut destination_group.entries_mut()[0];
        entry.set_field_and_commit("Title", "entry1_updated_from_destination");

        let mut entry = &mut source_group.entries_mut()[0];
        entry.set_field_and_commit("Title", "entry1_updated_from_source");

        let merge_result = destination_group.merge(&source_group).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 1);

        let entry = destination_group.entries()[0];
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
        let merge_result = destination_group.merge(&destination_group.clone()).unwrap();
        assert_eq!(merge_result.warnings.len(), 0);
        assert_eq!(merge_result.events.len(), 0);
    }
}
