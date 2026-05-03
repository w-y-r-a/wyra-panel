use mongodb::{
    bson::doc,
    options::ClientOptions,
    Client,
    options::IndexOptions,
    IndexModel,
};
use once_cell::sync::{OnceCell};
use mongodb::error::{ErrorKind, WriteFailure};

pub(crate) static CLIENT: OnceCell<mongodb::Client> = OnceCell::new();

pub(crate) async fn mongo_connect() -> mongodb::error::Result<()> {
    let mongodb_uri = crate::config::MONGO_URL.get().unwrap();

    let client_options = ClientOptions::parse(mongodb_uri).await
        .map_err(|e| mongodb::error::Error::custom(format!("Invalid MongoDB URI: {}", e)))?;
    let client = Client::with_options(client_options)?;
    client.database("admin").run_command(doc! { "ping": 1 }).await?;

    CLIENT.set(client).map_err(|_| {
        mongodb::error::Error::custom("MongoDB client already initialized")
    })?;

    tracing::info!("Connected to MongoDB!");
    Ok(())
}

pub(crate) async fn set_indexes() {
    tracing::info!("Setting MongoDB indexes...");
    
    let users_col = get_collection("users").expect("Failed to load users collection");
    let sessions_col = get_collection("sessions").expect("Failed to load sessions collection");
    let groups_col = get_collection("groups").expect("Failed to load groups collection");

    let options = IndexOptions::builder()
        .unique(true)
        .build();
    
    let user_index_1 = IndexModel::builder()
        .keys(doc! { "id": 1})
        .options(options.clone())
        .build();
    
    let user_index_2 = IndexModel::builder()
        .keys(doc! { "username": 1})
        .options(options.clone())
        .build();
    
    users_col.create_index(user_index_1).await.expect("Failed to create index 1 for users");
    users_col.create_index(user_index_2).await.expect("Failed to create index 2 for users");
    
    let session_index = IndexModel::builder()
        .keys(doc! { "session_id": 1 })
        .options(options.clone())
        .build();
    
    sessions_col.create_index(session_index).await.expect("Failed to create index for sessions");
    
    let group_id_index = IndexModel::builder()
        .keys(doc! { "id": 1 })
        .options(options.clone())
        .build();

    let group_name_index = IndexModel::builder()
        .keys(doc! { "name": 1 })
        .options(options)
        .build();
    
    groups_col.create_index(group_id_index).await.expect("Failed to create index for groups");
    groups_col.create_index(group_name_index).await.expect("Failed to create index for groups");
}

#[allow(dead_code)]
pub(crate) fn get_collection(
    collection_name: &str
) -> Result<mongodb::Collection<mongodb::bson::Document>, mongodb::error::Error> {
    let client = CLIENT.get().ok_or_else(|| {
        mongodb::error::Error::custom("MongoDB client not initialized")
    })?;
    Ok(client
        .database("wsp")
        .collection::<mongodb::bson::Document>(collection_name))
}

pub(crate) async fn mongo_shutdown() {
    tracing::info!("Attempting MongoDB shutdown...");

    let client = match CLIENT.get() {
        Some(c) => c.clone(),
        None => {
            tracing::warn!("mongo_shutdown() called but MongoDB was never initialized.");
            return;
        }
    };

    client.shutdown().await;

    tracing::info!("MongoDB shutdown complete.");
}

pub(crate) fn is_duplicate_key_error(err: &mongodb::error::Error) -> bool {
    matches!(
        err.kind.as_ref(),
        ErrorKind::Write(WriteFailure::WriteError(write_err)) if write_err.code == 11000
    )
}