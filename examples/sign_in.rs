//! Explicit interactive example; never run by the automated test suite.
use std::process::ExitCode;

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    // Returning the error from `main` would print `Debug`, which only names the
    // variant. `Display` says what to do.
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args_os()
        .nth(1)
        .ok_or("Pass a directory for the credentials: a new path, or a directory with mode 0700")?;
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
