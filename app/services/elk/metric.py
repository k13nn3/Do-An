from elasticsearch import Elasticsearch
from app.utils.helpers import get_nested_value

es = Elasticsearch(
    "https://192.168.10.140:9200",
    basic_auth=("elastic", "elastic"),
    verify_certs=False
)

def get_metric(host_filter=None):
    metrics = {}
    try:
        must_host = []
        if host_filter:
            must_host.append({"match": {"host.name": host_filter}})

        if host_filter:
            host_check = es.search(
                index="metricbeat-*",
                size=0,
                query={"bool": {"must": [{"match": {"host.name": host_filter}}]}},
                track_total_hits=True
            )
            if host_check["hits"]["total"]["value"] == 0:
                return f"⚠️ Không tìm thấy host `{host_filter}` trong dữ liệu Metricbeat.`"

        def latest(dataset, fields, extra_filter=None):
            query = {"bool": {"must": [{"match": {"event.dataset": dataset}}] + must_host}}
            if extra_filter:
                query["bool"]["filter"] = extra_filter
            return es.search(
                index="metricbeat-*",
                size=1,
                sort=[{"@timestamp": {"order": "desc"}}],
                query=query,
                _source=fields
            )

        res_cpu = latest("system.cpu", ["host.hostname", "@timestamp", "system.cpu.total.pct"],
                         [{"exists": {"field": "system.cpu.total.pct"}}])
        if res_cpu["hits"]["hits"]:
            src = res_cpu["hits"]["hits"][0]["_source"]
            metrics["host"] = src.get("host", {}).get("hostname", "unknown")
            metrics["time"] = src["@timestamp"]
            metrics["cpu"] = float(get_nested_value(src, "system.cpu.total.pct", 0)) * 100

        res_mem = latest("system.memory", ["system.memory.used.pct", "system.memory.swap.used.pct"],
                         [{"exists": {"field": "system.memory.used.pct"}}])
        if res_mem["hits"]["hits"]:
            src = res_mem["hits"]["hits"][0]["_source"]
            metrics["mem"] = float(get_nested_value(src, "system.memory.used.pct", 0)) * 100
            metrics["swap"] = float(get_nested_value(src, "system.memory.swap.used.pct", 0)) * 100

        res_load = latest("system.load", ["system.load.1", "system.load.5", "system.load.15"])
        if res_load["hits"]["hits"]:
            src = res_load["hits"]["hits"][0]["_source"]
            metrics["load1"] = get_nested_value(src, "system.load.1", 0)
            metrics["load5"] = get_nested_value(src, "system.load.5", 0)
            metrics["load15"] = get_nested_value(src, "system.load.15", 0)

        res_net = latest("system.network", [
            "system.network.in.bytes",
            "system.network.out.bytes",
            "system.network.in.packets",
            "system.network.out.packets",
            "system.network.in.dropped",
            "system.network.out.dropped"
        ], [{"exists": {"field": "system.network.in.bytes"}}])
        if res_net["hits"]["hits"]:
            src = res_net["hits"]["hits"][0]["_source"]
            metrics["net_in_mb"] = float(get_nested_value(src, "system.network.in.bytes", 0)) / (1024**2)
            metrics["net_out_mb"] = float(get_nested_value(src, "system.network.out.bytes", 0)) / (1024**2)
            metrics["packets_in"] = float(get_nested_value(src, "system.network.in.packets", 0))
            metrics["packets_out"] = float(get_nested_value(src, "system.network.out.packets", 0))
            metrics["drop_in"] = float(get_nested_value(src, "system.network.in.dropped", 0))
            metrics["drop_out"] = float(get_nested_value(src, "system.network.out.dropped", 0))

        res_disk = latest("system.filesystem", ["system.filesystem.used.pct"],
                          [{"term": {"system.filesystem.mount_point.keyword": "/"}}])
        if res_disk["hits"]["hits"]:
            src = res_disk["hits"]["hits"][0]["_source"]
            metrics["disk"] = float(get_nested_value(src, "system.filesystem.used.pct", 0)) * 100

        res_proc = latest("system.process.summary", ["system.process.summary.total"])
        if res_proc["hits"]["hits"]:
            src = res_proc["hits"]["hits"][0]["_source"]
            metrics["proc_total"] = int(get_nested_value(src, "system.process.summary.total", 0))

        msg = (
            f"*📊 System Metrics — {metrics.get('host', host_filter or 'unknown')}*\n"
            f"> 🕓 {metrics.get('time','N/A')}\n"
            f"> 🖥️ CPU: {metrics.get('cpu',0):.1f}%\n"
            f"> 💾 Memory: {metrics.get('mem',0):.1f}% | Swap: {metrics.get('swap',0):.1f}%\n"
            f"> 📈 Load (1/5/15): {metrics.get('load1',0):.2f} / {metrics.get('load5',0):.2f} / {metrics.get('load15',0):.2f}\n"
            f"> 🌐 Network: {metrics.get('net_in_mb',0):.2f} MB in / {metrics.get('net_out_mb',0):.2f} MB out\n"
            f"> ⚙️ Processes: {metrics.get('proc_total',0)} total\n"
            f"> 💽 Disk (/): {metrics.get('disk',0):.1f}%"
        )
        return msg

    except Exception as e:
        return f"⚠️ Lỗi khi truy vấn Metricbeat: {e}"
