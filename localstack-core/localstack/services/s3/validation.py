import datetime

from botocore.utils import InvalidArnException
from zoneinfo import ZoneInfo

from localstack.aws.api import CommonServiceException
from localstack.aws.api.s3 import (
    AccessControlPolicy,
    AnalyticsConfiguration,
    AnalyticsId,
    BucketCannedACL,
    BucketLifecycleConfiguration,
    BucketName,
    CORSConfiguration,
    Grant,
    Grantee,
    Grants,
    IntelligentTieringConfiguration,
    IntelligentTieringId,
    InvalidArgument,
    InvalidBucketName,
    InventoryConfiguration,
    InventoryId,
    KeyTooLongError,
    ObjectCannedACL,
    Permission,
    WebsiteConfiguration,
)
from localstack.aws.api.s3 import Type as GranteeType
from localstack.services.s3 import constants as s3_constants
from localstack.services.s3.exceptions import InvalidRequest, MalformedACLError, MalformedXML
from localstack.services.s3.utils import (
    _create_invalid_argument_exc,
    get_class_attrs_from_spec_class,
    get_permission_header_name,
    is_bucket_name_valid,
    is_valid_canonical_id,
    validate_dict_fields,
)
from localstack.utils.aws import arns
from localstack.utils.strings import to_bytes

# https://docs.aws.amazon.com/AmazonS3/latest/userguide/acl-overview.html#canned-acl
# bucket-owner-read + bucket-owner-full-control are allowed, but ignored for buckets
VALID_CANNED_ACLS = get_class_attrs_from_spec_class(
    BucketCannedACL
) | get_class_attrs_from_spec_class(ObjectCannedACL)


def validate_bucket_analytics_configuration(
    id: AnalyticsId, analytics_configuration: AnalyticsConfiguration
) -> None:
    if id != analytics_configuration.get("Id"):
        raise MalformedXML(
            "The XML you provided was not well-formed or did not validate against our published schema"
        )


def validate_bucket_intelligent_tiering_configuration(
    id: IntelligentTieringId, intelligent_tiering_configuration: IntelligentTieringConfiguration
) -> None:
    if id != intelligent_tiering_configuration.get("Id"):
        raise MalformedXML(
            "The XML you provided was not well-formed or did not validate against our published schema"
        )


def validate_bucket_name(bucket: BucketName) -> None:
    """
    Validate s3 bucket name based on the documentation
    ref. https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucketnamingrules.html
    """
    if not is_bucket_name_valid(bucket_name=bucket):
        raise InvalidBucketName("The specified bucket is not valid.", BucketName=bucket)


def validate_canned_acl(canned_acl: str) -> None:
    """
    Validate the canned ACL value, or raise an Exception
    """
    if canned_acl and canned_acl not in VALID_CANNED_ACLS:
        ex = _create_invalid_argument_exc(None, "x-amz-acl", canned_acl)
        raise ex


def parse_grants_in_headers(permission: Permission, grantees: str) -> Grants:
    splitted_grantees = [grantee.strip() for grantee in grantees.split(",")]
    grants = []
    for seralized_grantee in splitted_grantees:
        grantee_type, grantee_id = seralized_grantee.split("=")
        grantee_id = grantee_id.strip('"')
        if grantee_type not in ("uri", "id", "emailAddress"):
            ex = _create_invalid_argument_exc(
                "Argument format not recognized",
                get_permission_header_name(permission),
                seralized_grantee,
            )
            raise ex
        elif grantee_type == "uri":
            if grantee_id not in s3_constants.VALID_ACL_PREDEFINED_GROUPS:
                ex = _create_invalid_argument_exc("Invalid group uri", "uri", grantee_id)
                raise ex
            grantee = Grantee(
                Type=GranteeType.Group,
                URI=grantee_id,
            )

        elif grantee_type == "id":
            if not is_valid_canonical_id(grantee_id):
                ex = _create_invalid_argument_exc("Invalid id", "id", grantee_id)
                raise ex
            grantee = Grantee(
                Type=GranteeType.CanonicalUser,
                ID=grantee_id,
                DisplayName="webfile",  # TODO: only in certain regions
            )

        else:
            # TODO: check validation here
            grantee = Grantee(
                Type=GranteeType.AmazonCustomerByEmail,
                EmailAddress=grantee_id,
            )
        grants.append(Grant(Permission=permission, Grantee=grantee))

    return grants


def validate_acl_acp(acp: AccessControlPolicy) -> None:
    if acp is None or "Owner" not in acp or "Grants" not in acp:
        raise MalformedACLError(
            "The XML you provided was not well-formed or did not validate against our published schema"
        )

    if not is_valid_canonical_id(owner_id := acp["Owner"].get("ID", "")):
        ex = _create_invalid_argument_exc("Invalid id", "CanonicalUser/ID", owner_id)
        raise ex

    for grant in acp["Grants"]:
        if grant.get("Permission") not in s3_constants.VALID_GRANTEE_PERMISSIONS:
            raise MalformedACLError(
                "The XML you provided was not well-formed or did not validate against our published schema"
            )

        grantee = grant.get("Grantee", {})
        grant_type = grantee.get("Type")
        if grant_type not in (
            GranteeType.Group,
            GranteeType.CanonicalUser,
            GranteeType.AmazonCustomerByEmail,
        ):
            raise MalformedACLError(
                "The XML you provided was not well-formed or did not validate against our published schema"
            )
        elif (
            grant_type == GranteeType.Group
            and (grant_uri := grantee.get("URI", ""))
            not in s3_constants.VALID_ACL_PREDEFINED_GROUPS
        ):
            ex = _create_invalid_argument_exc("Invalid group uri", "Group/URI", grant_uri)
            raise ex

        elif grant_type == GranteeType.AmazonCustomerByEmail:
            # TODO: add validation here
            continue

        elif grant_type == GranteeType.CanonicalUser and not is_valid_canonical_id(
            (grantee_id := grantee.get("ID", ""))
        ):
            ex = _create_invalid_argument_exc("Invalid id", "CanonicalUser/ID", grantee_id)
            raise ex


def validate_lifecycle_configuration(lifecycle_conf: BucketLifecycleConfiguration) -> None:
    """
    Validate the Lifecycle configuration following AWS docs
    See https://docs.aws.amazon.com/AmazonS3/latest/userguide/intro-lifecycle-rules.html
    https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketLifecycleConfiguration.html
    :param lifecycle_conf: the bucket lifecycle configuration given by the client
    :raises MalformedXML: when the file doesn't follow the basic structure/required fields
    :raises InvalidArgument: if the `Date` passed for the Expiration is not at Midnight GMT
    :raises InvalidRequest: if there are duplicate tags keys in `Tags` field
    :return: None
    """
    # we only add the `Expiration` header, we don't delete objects yet
    # We don't really expire or transition objects
    # TODO: transition not supported not validated, as we don't use it yet
    if not lifecycle_conf:
        return

    for rule in lifecycle_conf.get("Rules", []):
        if any(req_key not in rule for req_key in ("ID", "Filter", "Status")):
            raise MalformedXML()
        if (non_current_exp := rule.get("NoncurrentVersionExpiration")) is not None:
            if all(
                req_key not in non_current_exp
                for req_key in ("NewerNoncurrentVersions", "NoncurrentDays")
            ):
                raise MalformedXML()

        if rule_filter := rule.get("Filter"):
            if len(rule_filter) > 1:
                raise MalformedXML()

        if (expiration := rule.get("Expiration", {})) and "ExpiredObjectDeleteMarker" in expiration:
            if len(expiration) > 1:
                raise MalformedXML()

        if exp_date := (expiration.get("Date")):
            if exp_date.timetz() != datetime.time(
                hour=0, minute=0, second=0, microsecond=0, tzinfo=ZoneInfo("GMT")
            ):
                raise InvalidArgument(
                    "'Date' must be at midnight GMT",
                    ArgumentName="Date",
                    ArgumentValue=exp_date.astimezone(),  # use the locale timezone, that's what AWS does (returns PST?)
                )

        if tags := (rule_filter.get("And", {}).get("Tags")):
            tag_keys = set()
            for tag in tags:
                if (tag_key := tag.get("Key")) in tag_keys:
                    raise InvalidRequest("Duplicate Tag Keys are not allowed.")
                tag_keys.add(tag_key)


def validate_website_configuration(website_config: WebsiteConfiguration) -> None:
    """
    Validate the website configuration following AWS docs
    See https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketWebsite.html
    :param website_config:
    :raises
    :return: None
    """
    if redirect_all_req := website_config.get("RedirectAllRequestsTo", {}):
        if len(website_config) > 1:
            ex = _create_invalid_argument_exc(
                message="RedirectAllRequestsTo cannot be provided in conjunction with other Routing Rules.",
                name="RedirectAllRequestsTo",
                value="not null",
            )
            raise ex
        if "HostName" not in redirect_all_req:
            raise MalformedXML()

        if (protocol := redirect_all_req.get("Protocol")) and protocol not in ("http", "https"):
            raise InvalidRequest(
                "Invalid protocol, protocol can be http or https. If not defined the protocol will be selected automatically."
            )

        return

    # required
    # https://docs.aws.amazon.com/AmazonS3/latest/API/API_IndexDocument.html
    if not (index_configuration := website_config.get("IndexDocument")):
        ex = _create_invalid_argument_exc(
            message="A value for IndexDocument Suffix must be provided if RedirectAllRequestsTo is empty",
            name="IndexDocument",
            value="null",
        )
        raise ex

    if not (index_suffix := index_configuration.get("Suffix")) or "/" in index_suffix:
        ex = _create_invalid_argument_exc(
            message="The IndexDocument Suffix is not well formed",
            name="IndexDocument",
            value=index_suffix or None,
        )
        raise ex

    if "ErrorDocument" in website_config and not website_config.get("ErrorDocument", {}).get("Key"):
        raise MalformedXML()

    if "RoutingRules" in website_config:
        routing_rules = website_config.get("RoutingRules", [])
        if len(routing_rules) == 0:
            raise MalformedXML()
        if len(routing_rules) > 50:
            raise ValueError("Too many routing rules")  # TODO: correct exception
        for routing_rule in routing_rules:
            redirect = routing_rule.get("Redirect", {})
            # todo: this does not raise an error? check what GetWebsiteConfig returns? empty field?
            # if not (redirect := routing_rule.get("Redirect")):
            #     raise "Something"

            if "ReplaceKeyPrefixWith" in redirect and "ReplaceKeyWith" in redirect:
                raise InvalidRequest(
                    "You can only define ReplaceKeyPrefix or ReplaceKey but not both."
                )

            if "Condition" in routing_rule and not routing_rule.get("Condition", {}):
                raise InvalidRequest(
                    "Condition cannot be empty. To redirect all requests without a condition, the condition element shouldn't be present."
                )

            if (protocol := redirect.get("Protocol")) and protocol not in ("http", "https"):
                raise InvalidRequest(
                    "Invalid protocol, protocol can be http or https. If not defined the protocol will be selected automatically."
                )


def validate_inventory_configuration(
    config_id: InventoryId, inventory_configuration: InventoryConfiguration
):
    """
    Validate the Inventory Configuration following AWS docs
    Validation order is XML then `Id` then S3DestinationBucket
    https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketInventoryConfiguration.html
    https://docs.aws.amazon.com/AmazonS3/latest/userguide/storage-inventory.html
    :param config_id: the passed Id parameter passed to the provider method
    :param inventory_configuration: InventoryConfiguration
    :raises MalformedXML: when the file doesn't follow the basic structure/required fields
    :raises IdMismatch: if the `Id` parameter is different from the `Id` field from the configuration
    :raises InvalidS3DestinationBucket: if S3 bucket is not provided as an ARN
    :return: None
    """
    required_root_fields = {"Destination", "Id", "IncludedObjectVersions", "IsEnabled", "Schedule"}
    optional_root_fields = {"Filter", "OptionalFields"}

    if not validate_dict_fields(
        inventory_configuration, required_root_fields, optional_root_fields
    ):
        raise MalformedXML()

    required_s3_bucket_dest_fields = {"Bucket", "Format"}
    optional_s3_bucket_dest_fields = {"AccountId", "Encryption", "Prefix"}

    if not (
        s3_bucket_destination := inventory_configuration["Destination"].get("S3BucketDestination")
    ) or not validate_dict_fields(
        s3_bucket_destination, required_s3_bucket_dest_fields, optional_s3_bucket_dest_fields
    ):
        raise MalformedXML()

    if inventory_configuration["Destination"]["S3BucketDestination"]["Format"] not in (
        "CSV",
        "ORC",
        "Parquet",
    ):
        raise MalformedXML()

    if not (frequency := inventory_configuration["Schedule"].get("Frequency")) or frequency not in (
        "Daily",
        "Weekly",
    ):
        raise MalformedXML()

    if inventory_configuration["IncludedObjectVersions"] not in ("All", "Current"):
        raise MalformedXML()

    possible_optional_fields = {
        "Size",
        "LastModifiedDate",
        "StorageClass",
        "ETag",
        "IsMultipartUploaded",
        "ReplicationStatus",
        "EncryptionStatus",
        "ObjectLockRetainUntilDate",
        "ObjectLockMode",
        "ObjectLockLegalHoldStatus",
        "IntelligentTieringAccessTier",
        "BucketKeyStatus",
        "ChecksumAlgorithm",
    }
    if (opt_fields := inventory_configuration.get("OptionalFields")) and set(
        opt_fields
    ) - possible_optional_fields:
        raise MalformedXML()

    if inventory_configuration.get("Id") != config_id:
        raise CommonServiceException(
            code="IdMismatch", message="Document ID does not match the specified configuration ID."
        )

    bucket_arn = inventory_configuration["Destination"]["S3BucketDestination"]["Bucket"]
    try:
        arns.parse_arn(bucket_arn)
    except InvalidArnException:
        raise CommonServiceException(
            code="InvalidS3DestinationBucket", message="Invalid bucket ARN."
        )


def validate_cors_configuration(cors_configuration: CORSConfiguration):
    rules = cors_configuration["CORSRules"]

    if not rules or len(rules) > 100:
        raise MalformedXML()

    required_rule_fields = {"AllowedMethods", "AllowedOrigins"}
    optional_rule_fields = {"AllowedHeaders", "ExposeHeaders", "MaxAgeSeconds", "ID"}

    for rule in rules:
        if not validate_dict_fields(rule, required_rule_fields, optional_rule_fields):
            raise MalformedXML()

        for method in rule["AllowedMethods"]:
            if method not in ("GET", "PUT", "HEAD", "POST", "DELETE"):
                raise InvalidRequest(
                    f"Found unsupported HTTP method in CORS config. Unsupported method is {method}"
                )


def validate_object_key(object_key: str) -> None:
    """
    ref. https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-keys.html

    """
    if (len_key := len(to_bytes(object_key, encoding="UTF-8"))) > 1024:
        raise KeyTooLongError(
            "Your key is too long",
            MaxSizeAllowed="1024",
            Size=str(len_key),
        )
