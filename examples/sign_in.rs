//! Explicit interactive example; never run by the automated test suite.
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args_os()
        .nth(1)
        .ok_or("Pass a private authentication directory")?;
    let auth = roomkit_auth::ChatGpt::new(path, "RoomKit Auth Example")?;
    let sign_in = auth.sign_in(None).await?;
    println!("Open in your browser: {}", sign_in.url());
    let account = sign_in.wait().await?;
    println!(
        "Connected account {} · plan usage: {}",
        account.id, account.plan_usage
    );
    if account.plan_usage {
        for model in auth.models(&account.id).await? {
            println!("{} · {}", model.id, model.name);
        }
    }
    Ok(())
}
