IMAGE_NAME ?= acme/java25-demo:latest

.PHONY: build test certify scan

build:
	docker build -t $(IMAGE_NAME) .

test:
	./tests/smoke.sh $(IMAGE_NAME)

certify:
	docker push $(IMAGE_NAME)
	APP_IMAGE="$(IMAGE_NAME)"; \
	APP_DIGEST=$$(docker buildx imagetools inspect "$$APP_IMAGE" --format '{{json .Manifest.Digest}}' | tr -d '"'); \
	docker save "$$APP_IMAGE" -o image.tar; \
	clearcutt-verify certify image.tar \
	  --policy policy.yaml \
	  --base java25-distroless \
	  --image-ref "$${APP_IMAGE%:*}@$${APP_DIGEST}"
	rm -f image.tar

scan:
	grype $(IMAGE_NAME)
