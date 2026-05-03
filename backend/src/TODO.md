- A much better groups system. Plugins should be able to export permission node (similar to Bukkit's) and then an API
could show all the permissions with this format: 
```json
[
  {
    "node": "plugin.perm",
    "description": "Node Description",
    "display_name": "Ability to do something"
  }
]
```
Note that individual permissions are NOT to be allowed, as this can be overlooked when trying to restructure an instance.
- More secure multi-node support. This means that a node can send a sort of "friend request" to another node, and the other node
is to respond with a 201 created and a "result_id" that the first node can use to check the status. This is to prevent spoofing and other security issues.
After the nodes are connected, they exchange keys that are used to sign requests, and the keys are rotated every 24 hours. This is to prevent replay attacks and other security issues.
Only users with the `core.node.manage` can accept or reject node connection requests.