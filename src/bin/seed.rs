use std::{env, fs};

use sqlx::postgres::PgPoolOptions;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv::dotenv().ok();

    let database_url = env::var("DATABASE_URL").unwrap_or_else(|_| {
        "postgresql://postgres:password@localhost:5432/guard_firearm_system".to_string()
    });

    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect(&database_url)
        .await?;

    let seed_sql = fs::read_to_string("seed_dashboard.sql")?;

    sqlx::query(&seed_sql).execute(&pool).await?;

    println!("Seeded dashboard data successfully.");

    Ok(())
}
