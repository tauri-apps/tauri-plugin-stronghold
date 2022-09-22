<script lang="ts">
  import { Stronghold, Location } from "tauri-plugin-stronghold-api";

  const stronghold = new Stronghold("./example.stronghold", "password");
  const location = Location.generic("vault", "record");
  const storeKey = "key";
  const clientPath = "client";

  let response = "";
  let record;

  async function getClient() {
    try {
      return await stronghold.loadClient(clientPath);
    } catch {
      return await stronghold.createClient(clientPath);
    }
  }

  function _updateResponse(returnValue) {
    response +=
      (typeof returnValue === "string"
        ? returnValue
        : JSON.stringify(returnValue)) + "<br>";
  }

  setTimeout(() => {
    _runProcedures()
      .then(() => _updateResponse("procedures finished"))
      .catch((e) => _updateResponse("error running procedures: " + e));
  }, 3000);

  async function _runProcedures() {
    const client = await getClient();
    const vault = client.getVault("exampleVault");
    const seedLocation = Location.generic("vault", "seed");
    await vault.generateBIP39(seedLocation);
    _updateResponse("generated bip39 mnemonic");
    const privateKeyLocation = Location.generic("vault", "derived");
    await vault.deriveSLIP10(
      [0, 0, 0],
      "Seed",
      seedLocation,
      privateKeyLocation
    );
    _updateResponse("SLIP10 derived");
    const publicKey = await vault.getEd25519PublicKey(privateKeyLocation);
    _updateResponse("got public key " + publicKey);
    const message = "Tauri + Stronghold!";
    const signature = await vault.sign(privateKeyLocation, message);
    _updateResponse(`Signed "${message}" and got sig "${signature}"`);
  }

  async function save() {
    const client = await getClient();
    const store = client.getStore();
    await store.insert(storeKey, Array.from(new TextEncoder().encode(record)));
    await stronghold.save();
  }

  async function read() {
    const client = await getClient();
    const store = client.getStore();
    store
      .get(storeKey)
      .then((value) => new TextDecoder().decode(new Uint8Array(value)))
      .then(_updateResponse)
      .catch(_updateResponse);
  }
</script>

<div>
  <input placeholder="The value to store" bind:value={record} />
  <button on:click={save}>Store</button>
</div>
<div>
  <button on:click={read}>Read</button>
  <div>{@html response}</div>
</div>

<style>
  html {
    background: #fff;
  }
</style>
