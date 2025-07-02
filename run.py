import blocklist_aggregator

unified = blocklist_aggregator.fetch(cfg_filename="blocklist_aggregator/blocklist.conf")

print(f"Fetched {len(unified)} domains.")
print("Saving domains in map format...")
blocklist_aggregator.save_map("outputs/blocklist_map.txt")
print("Completed saving map format.")
