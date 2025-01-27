FROM rust:latest

WORKDIR /app

COPY Cargo.toml .

RUN mkdir src && echo 'fn main() {}' > src/main.rs

RUN cargo build --release

COPY . .

RUN cargo build --release

CMD ["cargo", "test"]