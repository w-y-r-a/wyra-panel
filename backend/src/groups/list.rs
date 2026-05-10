use super::group_helpers::{get_group_info_from_str, GroupInfo};
use crate::{database::get_collection, helpers::{get_user_from_headers, Other, PanelResponse, PanelResult}};
use axum::http::{HeaderMap, StatusCode};
use bson::{doc, Document};
use futures::TryStreamExt;
use serde::Serialize;
use serde_json::{Map, Value};

// put into filter
#[derive(Serialize)]
struct DesiredFields {
    name: String,
    display_name: String,
    id: String,
    permissions: Vec<String>
}

// GET /groups/view
pub(crate) async fn view_groups_handler(
    //ConnectInfo(addr): ConnectInfo<SocketAddr>, /*not needed*/
    headers: HeaderMap,
) -> PanelResult {
    let user_cross_roads = get_user_from_headers(&headers).await?;
    let user = user_cross_roads.user;

    // validate if they have the permission 
    let groups = user.get_array("groups").expect("Failed to get groups from user").to_vec().iter().map(|g| g.as_str().unwrap().to_string()).collect::<Vec<String>>();

    let mut validated_groups: Vec<Option<GroupInfo>> = vec![];

    for group in groups {
        let group_info = get_group_info_from_str(group).await;
        validated_groups.push(group_info);
    }

    let mut onward = false;

    for group_opt in validated_groups {
        if let Some(group) = group_opt {
            if group.has_permission("core.groups.view") {
                onward = true;
                break;
            }
        }
    }

    if !onward {
        return Err((StatusCode::FORBIDDEN, PanelResponse {
            success: false,
            message: "You do not have permission(s) to view groups.".to_string(),
            other: None
        }));
    }

    // now get all the groups
    let groups_col = get_collection("groups").expect("Failed to load groups collection");

    let all_groups: Vec<Document> = groups_col.find(doc! {}).allow_partial_results(true).await.expect("Failed to get all groups").try_collect().await.expect("Failed to collect groups");
    
    let all_groups_desired: Vec<Value> = all_groups.iter().map(
        |i| {
            let mut map = Map::new();

            let mut permissions: Vec<String> = vec![];

            for permission in i.get_array("permissions").unwrap() {
                permissions.push(permission.as_str().unwrap().to_string());
            }

            map.insert("name".to_string(), Value::String(i.get_str("name").unwrap().to_string()));
            map.insert("display_name".to_string(), Value::String(i.get_str("display_name").unwrap().to_string()));
            map.insert("id".to_string(), Value::String(i.get_str("id").unwrap().to_string()));
            map.insert("permissions".to_string(), permissions.into());

            Value::Object(map)
        }
    ).collect();

    return Ok((
        StatusCode::OK,
        PanelResponse {
            success: true,
            message: "Loaded all groups".to_string(),
            other: Some(vec![
                Other {name: "groups".to_string(), field: serde_json::Value::Array(all_groups_desired)}
            ])
        }
    ))
}