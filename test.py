import hashlib
senha = "005582773MO041"
username = "160340"
print(hashlib.md5((senha + username).encode()).hexdigest())
# -> 0080fc1661ebe95e9c4bb8b5b65aee24
