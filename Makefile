dsds: main.go
	go build

deploy:
	docker build . -t rossigee/dsds && \
		docker push rossigee/dsds
