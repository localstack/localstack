resource "aws_route53_zone" "tf_route53_zone" {
  name = "test.example.com"
  tags = {
    name = "tf-route53-zone"
  }
}

resource "aws_route53_record" "tf_route53_record" {
  zone_id = aws_route53_zone.tf_route53_zone.zone_id
  name    = "test.example.com"
  type    = "A"
  ttl     = "1"
  records = ["1.1.1.1"]
}