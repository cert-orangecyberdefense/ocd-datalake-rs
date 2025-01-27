IMAGE_NAME = ocd-datalake-rs
CONTAINER_NAME = ocd-datalake-rs-container

build:
	docker build -t $(IMAGE_NAME) .

test: build
	docker-compose run --rm app cargo test

shell:
	docker-compose run --rm app /bin/bash

clean:
	docker rmi $(IMAGE_NAME)