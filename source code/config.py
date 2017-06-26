import ConfigParser
import os

abs_dir = os.path.dirname(os.path.abspath(__file__))
config_path = abs_dir+"/setting.cfg"
cfg = ConfigParser.SafeConfigParser()
cfg.read(config_path)

# Get config settings
nfs_dir = cfg.get("path", "nfs_dir")
report_dir = cfg.get("path", "report_dir")
netlist = cfg.get("path", "netlist")
netlist_v6 = cfg.get("path", "netlist_v6")
anomaly_log = cfg.get("path", "anomaly_log")
ignore_net = cfg.get("others", "ignore_net")
ignore_dns = cfg.get("others", "ignore_dns")
