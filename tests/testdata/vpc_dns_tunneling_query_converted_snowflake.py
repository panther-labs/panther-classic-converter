# nolint
from panther_sdk import detection

detection.ScheduledQuery(
    name="Query.VPC.DNS.Tunneling",
    enabled=False,
    tags=[],
    description="Detect activity similar to DNS tunneling traffic in AWS VPC Logs\n",
    sql="SELECT\n  account_id,\n  region,\n  vpc_id,\n  srcAddr, -- outside\n  srcIds:instance, -- inside\n\n  COUNT(1) as message_count,\n  ARRAY_AGG(DISTINCT query_name) as query_names\nFROM\n  panther_logs.public.aws_vpcdns\nWHERE\n  p_occurs_since(3600) -- 1 hour in seconds\n  AND\n  -- simple allowlisting\n  query_name NOT LIKE '%amazonaws.com'\nGROUP BY\n  1,2,3,4,5\nHAVING\n  message_count >= 1000   -- decent amount of activity in an hour\n  AND\n  ARRAY_SIZE(query_names) <= 2 -- only a small number of distinct domains (not likely a real dns server!)\n",
)
