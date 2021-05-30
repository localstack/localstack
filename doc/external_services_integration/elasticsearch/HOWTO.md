## Using custom Elasticsearch endpoint

This is a guide to use your own custom ES endpoint, please note this is not a how-to configure or setup Elasticsearch, to do that refer to the [official documentation](https://www.elastic.co/guide/index.html)


## Why is this useful?

Localstack downloads elasticserach asynchronously the first time you run the `aws es create-elasticsearch-domain`, so you will get the response from localstack first and then (after download/install) you will have your elasticsearch cluster running locally. 

In order to mitigate this you can run your own elasticsearch cluster locally and point localstack to it, so you can customize your setup and reduce waiting times.

## How to run it?

You can find the [example docker compose](docker-compose.yml) file which contains a single-noded elasticsearch cluster and a simple localstack setup, that should be enough for you to run the setup.

1. Run docker compose:
```
$ docker-compose up -d
```

2. Create the Elasticsearch domain:
```
$ awslocal es create-elasticsearch-domain --domain-name mylogs-2 --elasticsearch-version 7.10 --elasticsearch-cluster-config '{ "InstanceType": "m3.xlarge.elasticsearch", "InstanceCount": 4, "DedicatedMasterEnabled": true, "ZoneAwarenessEnabled": true, "DedicatedMasterType": "m3.xlarge.elasticsearch", "DedicatedMasterCount": 3}'

{
    "DomainStatus": {
        "DomainId": "000000000000/mylogs-2",
        "DomainName": "mylogs-2",
        "ARN": "arn:aws:es:us-east-1:000000000000:domain/mylogs-2",
        "Created": true,
        "Deleted": false,
        "Endpoint": "http://localhost:4571",
        "Processing": false,
        "ElasticsearchVersion": "7.10",
        "ElasticsearchClusterConfig": {
            "InstanceType": "m3.xlarge.elasticsearch",
            "InstanceCount": 4,
            "DedicatedMasterEnabled": true,
            "ZoneAwarenessEnabled": true,
            "DedicatedMasterType": "m3.xlarge.elasticsearch",
            "DedicatedMasterCount": 3
        },
        "EBSOptions": {
            "EBSEnabled": true,
            "VolumeType": "gp2",
            "VolumeSize": 10,
            "Iops": 0
        },
        "CognitoOptions": {
            "Enabled": false
        }
    }
}
```

3. Check the cluster health endpoint and create indices:
```
$ curl http://localhost:4571/_cluster/health
{"cluster_name":"es-docker-cluster","status":"green","timed_out":false,"number_of_nodes":1,"number_of_data_nodes":1,"active_primary_shards":0,"active_shards":0,"relocating_shards":0,"initializing_shards":0,"unassigned_shards":0,"delayed_unassigned_shards":0,"number_of_pending_tasks":0,"number_of_in_flight_fetch":0,"task_max_waiting_in_queue_millis":0,"active_shards_percent_as_number":100.0}[~]
```

4. Create an example index:
```
$ curl -X PUT  http://localhost:4571/my-index
{"acknowledged":true,"shards_acknowledged":true,"index":"my-index"}
```