<script lang="ts">
	import { Stronghold, Location } from 'tauri-plugin-stronghold-api'

	const stronghold = new Stronghold('./example.stronghold', 'password')
	const store = stronghold.getStore('exampleStoreVault', [])
	const vault = stronghold.getVault('exampleVault', [])
	const location = Location.generic('vault', 'record')

	stronghold.onStatusChange(status => {
		_updateResponse('got new stronghold status: ' + status.snapshot.status)
	})

	let response = '';
	let record;

	function _updateResponse(returnValue) {
		response += (typeof returnValue === 'string' ? returnValue : JSON.stringify(returnValue)) + '<br>'
	}

	_runProcedures().then(() => _updateResponse('procedures finished')).catch(e => _updateResponse('error running procedures: ' + e))

	async function _runProcedures() {
		const seedLocation = Location.generic('vault', 'seed')
		await vault.generateBIP39(seedLocation)
		const privateKeyLocation = Location.generic('vault', 'derived')
		await vault.deriveSLIP10([0, 0, 0], 'Seed', seedLocation, privateKeyLocation)
		const publicKey = await vault.getPublicKey(privateKeyLocation)
		_updateResponse('got public key ' + publicKey)
		const message = 'Tauri + Stronghold!'
		const signature = await vault.sign(privateKeyLocation, message)
		_updateResponse(`Signed "${message}" and got sig "${signature}"`)
	}

	async function save() {
		await store.insert(location, record)
		await stronghold.save()
	}

	function read() {
		store.get(location)
			.then(_updateResponse)
			.catch(_updateResponse)
	}
</script>

<style>
	html {
		background: #fff;
	}
</style>

<div>
	<input placeholder="The value to store" bind:value={record}>
	<button on:click="{save}">Store</button>
</div>
<div>
	<button on:click="{read}">Read</button>
	<div>{@html response}</div>
</div>