IMAGE_NAME = ocd-datalake-rs
CONTAINER_NAME = ocd-datalake-rs-container

build:
	docker compose build

test: build
	docker compose run --rm app cargo test

shell:
	docker compose run --rm app /bin/bash

clean:
	docker image rm $(IMAGE_NAME)
