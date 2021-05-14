FROM amazon/aws-lambda-nodejs:14 as base

FROM lambci/lambda:nodejs12.x

COPY --from=base /var/lang/bin/node /var/lang/bin/node
