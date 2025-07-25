
import sys
import yaml
import pkgutil
import requests
import logging
import re
import os
from datetime import date
import cdblib

def percent_list(part_list, whole_list):
    """return percent of the part"""
    w = len(whole_list)
    if not w:
        return (w,0)
    p = 100 * float(len(part_list))/float(w)
    return (w,round(100-p, 2))

def load_config(cfg_update=None, cfg_filename=None):
    """load YAML config"""
    try:
        if cfg_filename:
            with open(cfg_filename, 'r') as stream:
                cfg = yaml.safe_load(stream)
        else:
            conf = pkgutil.get_data(__package__, 'blocklist.conf')
            cfg = yaml.safe_load(conf)
        if cfg_update is not None:
            cfg.update(yaml.safe_load(cfg_update))
        return cfg
    except Exception as e:
        logging.error("Error loading config: %s" % e)
        sys.exit(1)
        
def inspect_source(pattern, string):
    """inspect string to find domains"""
    logging.debug("*** Searching valid domains...")

    # find all domains according to the pattern
    matched_domains = re.findall(pattern, string, re.M)

    # and eliminate duplicated domains
    domains = list(set(d for d in matched_domains))

    # calculate total domains and percent of duplication
    w,p = percent_list(domains,matched_domains)

    logging.debug("*** domains=%s duplicated=%s%%" % (w,p) )
    return domains
    
def fetch(cfg_update=None, cfg_filename=None):
    """fetch sources"""
    # read default config or from file
    cfg = load_config(cfg_update, cfg_filename)

    # init logger
    level = logging.INFO
    if cfg["verbose"]: level = logging.DEBUG
    logging.basicConfig(format='%(asctime)s %(message)s', 
                        stream=sys.stdout, level=level)
    
    domains_bl = []

    # feching all sources
    for s in cfg["sources"]:
        for u in s["urls"]:
            try:
                r = requests.get(u, timeout=float(cfg["timeout"]), verify=cfg["tlsverify"])
            except requests.exceptions.RequestException as e:
                logging.error("requests exception: %s" % e)
            else:
                if r.status_code != 200:
                    logging.error("http error: %s" % r.status_code)
                    continue
                else:
                    domains = inspect_source(s["pattern"], r.text)
                    if len(domains) == 0:
                        logging.error("no domains extracted for: %s" % u)
                        continue
                    domains_bl.extend(domains)  
            
    # add more domains to the blocklist ?
    if cfg["blacklist"] is not None:
        domains_bl.extend(cfg["blacklist"])
    
    # remove duplicated domains
    domains_unified = list(set(d for d in domains_bl))
    w,p = percent_list(domains_unified,domains_bl)
    logging.debug("blocklist origin=%s total=%s duplicated=%s%%" % (len(domains_bl), len(domains_unified),p))
    
    # apply the whilelist
    set_domains = set(domains_unified)
    set_whitelist = set(cfg["whitelist"])
    set_domains.difference_update(set_whitelist)
    domains_unified = list(set_domains)
    logging.debug("final blocklist with whitelist applied total=%s" % len(domains_unified))
    
    return domains_unified

def fetch_with_sources(cfg_update=None, cfg_filename=None):
    """fetch sources with associated URLs"""
    # load config
    cfg = load_config(cfg_update, cfg_filename)
    
    # init logger
    level = logging.INFO
    if cfg["verbose"]: level = logging.DEBUG
    logging.basicConfig(format='%(asctime)s %(message)s', 
                        stream=sys.stdout, level=level)

    domain_to_source = {}

    # feching all sources
    for s in cfg.get("sources", []):
        pattern = s["pattern"]
        for u in s["urls"]:
            try:
                r = requests.get(u, timeout=float(cfg["timeout"]), verify=cfg["tlsverify"])
                if r.status_code != 200:
                    logging.error(f"HTTP error {r.status_code} for {u}")
                    continue
                domains = inspect_source(pattern, r.text)
                for d in domains:
                    domain_to_source[d] = u
            except Exception as e:
                logging.error(f"Request failed for {u}: {e}")
    
    # add blacklist domains
    blacklist = set(cfg.get("blacklist", []))
    for b in blacklist:
        if b not in domain_to_source:
            domain_to_source[b] = "local:blacklist"
    
    # apply whitelist
    whitelist = set(cfg.get("whitelist", []))
    for w in whitelist:
        domain_to_source.pop(w, None)
    
    return domain_to_source

def save_to_file(filename, data):
    """save to file"""
    try:
        with open(filename, 'w') as f:
            f.write(data)
    except Exception as e:
        logging.error("unable to save to file: %s" % e)
        return False
    return True

def save_raw(filename, cfg_update=None, cfg_filename=None):
    """save to file with raw format"""
    # feching bad domains
    domains = fetch(cfg_update=cfg_update, cfg_filename=cfg_filename)

    # to avoid empty file
    if len(domains) == 0:
        logging.error("nothing to write, the domain list is empty!")
        return
    
    raw = [ "# Generated with blocklist-aggregator" ]
    raw.append( "# Updated: %s" % date.today() )
    raw.append( "" )
    
    raw.extend(domains)
    
    success = save_to_file(filename, "\n".join(raw) )
    if success: 
        logging.debug("raw file saved")
    
def save_hosts(filename, ip="0.0.0.0", cfg_update=None, cfg_filename=None):
    """save to file with hosts format"""
    # feching bad domains
    domains = fetch(cfg_update=cfg_update, cfg_filename=cfg_filename)
    
    # to avoid empty file
    if len(domains) == 0:
        logging.error("nothing to write, the domain list is empty!")
        return
    
    hosts = [ "# Generated with blocklist-aggregator" ]
    hosts.append( "# Updated: %s" % date.today() )
    hosts.append( "" )
    
    domains_ = list(map(lambda p: "%s " % ip + p, domains))
    hosts.extend(domains_)
    
    # save-it in a file
    success = save_to_file(filename, "\n".join(hosts) )
    if success:
        logging.debug("hosts file saved")

def save_map(filename, cfg_update=None, cfg_filename=None):
    """
    Save to file with TinyCDB map format: <domain><tab><source-url>
    """
    # fetching domains w/ sources
    domains = fetch_with_sources(cfg_update=cfg_update, cfg_filename=cfg_filename)

    # to avoid empty file
    if len(domains) == 0:
        logging.error("nothing to write, the domain list is empty!")
        return

    map = [ "# Generated with blocklist-aggregator" ]
    map.append( "# Updated: %s" % date.today() )
    map.append( "" )

    for domain, source in domains.items():
        map.append(f"{domain} {source}")
    
    success = save_to_file(filename, "\n".join(map))
    if success:
        logging.debug("map file saved")

def save_cdb(filename, default_value="", cfg_update=None, cfg_filename=None):
    """save to CDB database"""
    # feching domains
    domains = fetch(cfg_update=cfg_update, cfg_filename=cfg_filename)

    # to avoid empty file
    if len(domains) == 0:
        logging.error("nothing to write, the domain list is empty!")
        return
    
    try:
        with open(filename, 'wb') as f:
            with cdblib.Writer(f) as writer:
                for d in domains:
                    writer.put(d.encode(), default_value.encode())
    except Exception as e:
        logging.error("error to save in cdb file: %s" % e)
    else:
        logging.debug("cdb file saved with success")

def save_cdb_from_map(map_filename, cdb_filename):
    """
    Load a domain-to-source map file and write it to a CDB file.
    Format of map file: <domain> <source-url>
    """
    entries = {}

    try:
        with open(map_filename, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                try:
                    domain, source = line.split(None, 1)
                    entries[domain.strip()] = source.strip()
                except ValueError:
                    logging.warning(f"Skipping malformed line in map file: {line}")
    except Exception as e:
        logging.error(f"Error reading map file {map_filename}: {e}")
        return
    
    if not entries:
        logging.error("No valid entries found in the map file.")
        return
    
    try:
        with open(cdb_filename, 'wb') as f:
            with cdblib.Writer(f) as writer:
                for domain, source in entries.items():
                    writer.put(domain.encode(), source.encode())
        logging.debug(f"CDB file {cdb_filename} written successfully with {len(entries)} entries.")
    except Exception as e:
        logging.error(f"Error writing CDB file {cdb_filename}: {e}")