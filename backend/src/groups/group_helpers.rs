use std::collections::HashMap;
use bson::doc;
use serde::{Serialize, Deserialize};
use crate::{database::get_collection, AVAILABLE_PERMISSIONS};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Permissions {
    pub(crate) nodes: Vec<String>,
    pub(crate) all_access: bool
}

impl Permissions {
    pub fn contains(&self, node: &str) -> bool {
        if self.all_access {
            return true;
        }
        if self.nodes.contains(&node.to_string()) {
            return true;
        }
        for perm in &self.nodes {
            if let Some(prefix) = perm.strip_suffix(".*") {
                if node.starts_with(&format!("{}.", prefix)) {
                    return true;
                }
            }
        }
        false
    }
}

impl GroupInfo {
    pub fn has_permission(&self, node: &str) -> bool {
        //! Checks if the group has the permission node specified.
        //! If the group has the `*` node, they naturally have access
        //! to everything.

        // still allow the contains to be pub, because you never know, it may be useful.
        self.permissions.contains(node) // neater wrapper
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GroupInfo {
    pub name: String,
    pub display_name: String,
    pub group_id: String,
    pub permissions: Permissions
}

pub async fn get_group_info_from_str(name: String) -> Option<GroupInfo> {
    let groups_collection = get_collection("groups").expect("Failed to get groups collection");

    let group = match groups_collection.find_one(doc! { "name": &name}).await.unwrap() {
        Some(group) => group,
        None => return None
    };

    let mut perm_struct = Permissions {nodes: vec![], all_access: false};

    let permissions = group.get_array("permissions").unwrap().to_vec().iter().map(|p| p.as_str().unwrap().to_string()).collect::<Vec<String>>();

    if permissions.contains(&"*".to_string()) {
        perm_struct.all_access = true;
    }

    perm_struct.nodes = permissions;


    Some(GroupInfo {
        name,
        display_name: group.get_str("display_name").unwrap().to_string(),
        group_id: group.get_str("id").unwrap().to_string(),
        permissions: perm_struct
    })
}

pub(crate) fn init_permissions() {
    //TODO: Integrate with the plugin api to get loaded plugins and their permissions, and add them to the available permissions list.

    let mut core_permissions: HashMap<String, String> = HashMap::new();
    let mut permissions: HashMap<String, String> = HashMap::new();

    core_permissions.insert("*".to_string(), "Access to all permissions".to_string());
    core_permissions.insert("core.node.manage".to_string(), "Manage nodes, gives all access to node management.".to_string());
    core_permissions.insert("core.node.manage.connections".to_string(), "Gives ability to accept and reject node connections.".to_string());
    core_permissions.insert("core.users.manage.create".to_string(), "Gives ability to create users.".to_string());
    core_permissions.insert("core.users.manage.disable".to_string(), "Gives ability to disable users.".to_string());
    core_permissions.insert("core.users.manage.delete".to_string(), "Gives ability to delete users.".to_string());
    core_permissions.insert("core.users.manage.update.info".to_string(), "Gives ability to update info for users.".to_string());
    core_permissions.insert("core.users.manage.update.permissions".to_string(), "Gives ability to update permissions for users.".to_string());
    core_permissions.insert("core.users.manage.update".to_string(), "Gives ability to update users. (permissions and info)".to_string());

    // the following is pseudocode for how we would register permissions
    // let plugins_permissions: Vec<HashMap<String, String>> = get_all_plugins().permissions;
    // for plugin_perms in plugins_permissions {
    //     for (node, desc) in plugin_perms {
    //         permissions.insert(node, desc);
    //     }
    // }

    for (node, desc) in core_permissions {
        permissions.insert(node, desc);
    }

    AVAILABLE_PERMISSIONS.set(permissions).expect("Failed to set permissions for AVAILABLE_PERMISSIONS");

}