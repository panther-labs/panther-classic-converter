# nolint
def use():
    from panther_config import detection

    detection.ScheduledQuery(
        name="Query.VPC.DNS.Tunneling",
        enabled=False,
        tags=[],
        description="Detect activity similar to DNS tunneling traffic in AWS VPC Logs\n",
        sql="/* athena query not supported */ SELECT count(1)\n",
    )
