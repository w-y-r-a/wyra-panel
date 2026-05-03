use bson::doc;
// this module is not a route
use crate::database::get_collection;
use uuid::Uuid;

pub(crate) async fn create_admin_group() {
    let groups_collection = get_collection("groups").expect("Failed to get groups collection");

    let _id = groups_collection.insert_one(doc! {
        "name": "admin",
        "display_name": "Administrator",
        "id": Uuid::new_v4().to_string(),
        "permissions": ["*"]
    }).await.expect("Failed to create admin group").inserted_id;

    tracing::info!(inserted_id=_id.as_object_id().unwrap().to_string(), "Created Admin Group");
}