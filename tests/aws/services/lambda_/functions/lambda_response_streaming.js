exports.handler = awslambda.streamifyResponse(
    async (event, responseStream, context) => {
        const metadata = {
            status: 200,
            headers: {
                'Content-Type': 'text/html',
                'Cache-Control': 'no-cache',
            },
        }

        responseStream = awslambda.HttpResponseStream.from(responseStream, metadata)

        responseStream.write('Hello,');
        responseStream.write(' world!');
        responseStream.end();
    }
);
