<script lang="ts">
  import {
    Stronghold,
    Location,
    setPasswordClearInterval,
  } from "tauri-plugin-stronghold-api";
  import { copyFile, removeFile } from "@tauri-apps/api/fs";

  let response = "";
  let record;
  let defaultPassword = "password";
  let currentPassword = defaultPassword;
  let password = "";
  let newPassword;
  let reinitPassword = "";
  let clearInterval;
  let isLocked;

  let strongholdPath = "./example.stronghold";
  let stronghold = new Stronghold(strongholdPath, defaultPassword);
  let store = stronghold.getStore("exampleStoreVault", []);
  let vault = stronghold.getVault("exampleVault", []);
  let location = Location.generic("vault", "record");

  stronghold.onStatusChange((status) => {
    _updateResponse("got new stronghold status: " + status.snapshot.status);
    isLocked = status.snapshot.status === "Locked";
  });

  function _updateResponse(returnValue) {
    response +=
      (typeof returnValue === "string"
        ? returnValue
        : JSON.stringify(returnValue)) + "<br>";

    const outputDiv = document.getElementById("output");
    outputDiv.scroll({ top: outputDiv.scrollHeight, behavior: "smooth" });
  }

  _runProcedures()
    .then(() => _updateResponse("procedures finished"))
    .catch((e) => _updateResponse("error running procedures: " + e));

  async function _runProcedures() {
    const seedLocation = Location.generic("vault", "seed");
    await vault.generateBIP39(seedLocation);
    const privateKeyLocation = Location.generic("vault", "derived");
    await vault.deriveSLIP10(
      [0, 0, 0],
      "Seed",
      seedLocation,
      privateKeyLocation
    );
    const publicKey = await vault.getPublicKey(privateKeyLocation);
    _updateResponse("got public key " + publicKey);
    const message = "Tauri + Stronghold!";
    const signature = await vault.sign(privateKeyLocation, message);
    _updateResponse(
      `Signed message "${message}" and got signature "${signature}"`
    );
  }

  async function save() {
    try {
      await store.insert(location, record);
      await stronghold.save();
      _updateResponse(`Record stored: ${record}`);
      record = "";
    } catch (err) {
      _updateResponse(err);
    }
  }

  async function read() {
    try {
      const response = await store.get(location);
      _updateResponse(`Record read: ${response}`);
    } catch (err) {
      _updateResponse(err);
    }
  }

  async function getStatus() {
    try {
      const status = await stronghold.getStatus();
      _updateResponse(`Status: ${status.snapshot.status}`);
    } catch (err) {
      _updateResponse(err);
    }
  }

  async function setClearInterval() {
    try {
      await setPasswordClearInterval({ secs: Number(clearInterval), nanos: 0 });
      _updateResponse(
        `Locking stronghold after ${clearInterval} seconds of inactivity`
      );
      clearInterval = "";
    } catch (err) {
      _updateResponse(err);
    }
  }

  async function lock() {
    try {
      // Clear the password as fast as possible
      await setPasswordClearInterval({ secs: 0, nanos: 1 });
    } catch (err) {
      _updateResponse(err);
    }
  }

  async function unlock() {
    try {
      await stronghold.reload(password);

      // Interval of 0 means the password is never cleared
      await setPasswordClearInterval({ secs: 0, nanos: 0 });
      password = "";
    } catch (err) {
      _updateResponse(err);
    }
  }

  async function changePassword() {
    try {
      // backup current stronghold
      await copyFile(strongholdPath, `${strongholdPath}.backup`);

      // read the contents
      const oldRecord = await store.get(location);

      // delete current vault
      await stronghold.unload();
      await removeFile(strongholdPath);

      // create new stronghold with new password
      stronghold = new Stronghold(strongholdPath, newPassword);
      store = stronghold.getStore("exampleStoreVault", []);

      // save old record to new stronghold store
      await store.insert(location, oldRecord);
      await stronghold.save();
      _updateResponse(`Password changed to "${newPassword}"`);

      // delete backup
      await removeFile(`${strongholdPath}.backup`);

      currentPassword = newPassword;
      newPassword = "";
    } catch (err) {
      _updateResponse(err);
    }
  }

  async function reinit() {
    try {
      await stronghold.unload();
      stronghold = new Stronghold(strongholdPath, reinitPassword);
      reinitPassword = "";
    } catch (err) {
      _updateResponse(err);
    }
  }

  async function destroy() {
    try {
      await stronghold.unload();
      await removeFile(strongholdPath);
    } catch (err) {
      _updateResponse(err);
    }
  }
</script>

<div class="container">
  <div class="column">
    <div class="section">
      <div class="label">Store a value</div>
      <input placeholder="Value" bind:value={record} />
      <button on:click={save}>Store</button>
    </div>
    <div class="section">
      <div class="label">Read stronghold</div>
      <button on:click={read}>Read Value</button>
      <button on:click={getStatus}>Get Status</button>
    </div>
    <div class="section">
      <div class="label">Reinit w/ password</div>
      <input placeholder="Password" bind:value={reinitPassword} />
      <button on:click={reinit}>Init</button>
    </div>
    <div class="section">
      <div class="label">Delete stronghold</div>
      <button on:click={destroy}>Destroy</button>
    </div>
  </div>
  <div class="column">
    <div class="section">
      <div class="label">
        Lock / Unlock <span>(current password: "{currentPassword}")</span>
      </div>
      {#if !isLocked}
        <button on:click={lock}>Lock</button>
      {:else}
        <input placeholder="Password" bind:value={password} />
        <button on:click={unlock}>Unlock</button>
      {/if}
    </div>
    <div class="section">
      <div class="label">Set password clear interval</div>
      <input placeholder="Seconds" bind:value={clearInterval} />
      <button on:click={setClearInterval}>Set</button>
    </div>
    <div class="section">
      <div class="label">Change password</div>
      <input placeholder="New Password" bind:value={newPassword} />
      <button on:click={changePassword}>Change</button>
    </div>
  </div>
</div>
<div class="footer">
  <div class="label">Output:</div>
  <div id="output">{@html response}</div>
</div>

<style>
  :global(body) {
    background: #ffffff;
    color: #32363b;
    display: flex;
    flex-direction: column;
  }

  @media (prefers-color-scheme: dark) {
    :global(body) {
      background: #32363b;
      color: #ffffff;
    }

    #output {
      background: #ffffff;
    }
  }

  .container {
    display: flex;
  }

  .column {
    flex: 1;
  }

  .section {
    margin-bottom: 0.5rem;
  }

  .footer {
    margin-top: auto;
  }

  .label {
    font-weight: bold;
    margin-bottom: 0.5rem;
  }

  .label span {
    font-weight: normal;
  }

  #output {
    background: #ebebeb;
    color: #000000;
    font-family: monospace;
    font-size: 0.9rem;
    line-height: 1.5;
    padding: 0.5rem 0.7rem 2rem;
    height: 200px;
    overflow: auto;
  }
</style>
