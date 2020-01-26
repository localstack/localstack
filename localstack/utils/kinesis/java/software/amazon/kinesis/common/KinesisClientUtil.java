/*
 * Copyright 2019 Amazon.com, Inc. or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package software.amazon.kinesis.common;

import software.amazon.awssdk.http.nio.netty.NettyNioAsyncHttpClient;
import software.amazon.awssdk.services.kinesis.KinesisAsyncClient;
import software.amazon.awssdk.services.kinesis.KinesisAsyncClientBuilder;
import software.amazon.awssdk.http.Protocol;

/**
 * Utility to setup KinesisAsyncClient to be used with KCL.
 */
public class KinesisClientUtil {

    /**
     * Creates a client from a builder.
     *
     * @param clientBuilder
     * @return
     */
    public static KinesisAsyncClient createKinesisAsyncClient(KinesisAsyncClientBuilder clientBuilder) {
        return adjustKinesisClientBuilder(clientBuilder).build();
    }

    public static KinesisAsyncClientBuilder adjustKinesisClientBuilder(KinesisAsyncClientBuilder builder) {
        return builder.httpClientBuilder(NettyNioAsyncHttpClient.builder()
                .maxConcurrency(Integer.MAX_VALUE).protocol(Protocol.HTTP1_1));
    }
}
