"""
Usage reporting for SNS internal endpoints
"""

from localstack.utils.analytics.usage import UsageSetCounter

# number of times SNS internal endpoint per resource types
# (e.g. PlatformMessage:get invoked 10x times, SMSMessage:get invoked 3x times, SubscriptionToken...)
internalapi = UsageSetCounter("sns:internalapi")
