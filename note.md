docker run --privileged --name dind -d -v $PWD:/workspace docker:dind

docker exec -it dind sh

docker run \
              --tty --rm \
              --volume ~/.cache/hs-integration-go:/go \
              --name headscale-test-suite \
              --volume $PWD:$PWD -w $PWD/integration \
              --volume /var/run/docker.sock:/var/run/docker.sock \
              --volume $PWD/control_logs:/tmp/control \
              --env HEADSCALE_INTEGRATION_POSTGRES=0 \
              golang:1 \
                go run gotest.tools/gotestsum@latest -- ./... \
                  -failfast \
                  -timeout 120m \
                  -parallel 1 \
                  -run "TestDERPVerify" -v