import "fake-indexeddb/auto";
import 'localstorage-polyfill'
import { WalletStatus, walletFactory, KeyResolver } from '../wallet'
import { QueryContent2020, WalletContent2020 } from "@pixi-wallet/components";
import { toSign as firstToSign, toDerive, toVerify, defaultAudience, encodeKey } from "@pixi-wallet/ucan-plugin";

import { EdKeypair } from "@mkabanau/default-plugins"

const key1 = EdKeypair.fromSecretKey('det3ec7YeBkTtQE1zuWINWnv2ne3d4f5Rd1yLKIc+kkgPiE5HqIXDdc/UoZgElCbdUEBIg1qz5OzR4GXpY87pA==', { exportable: true })
const key2 = EdKeypair.fromSecretKey('CRTdULZAfj8F7j09gYSjMEGWhrxvJwCtnbYMVEw7U8qPUFVXkghGkpvWg4OJd+LBHeGxnu1DKGlNAZRg7mMtOQ==', { exportable: true })

function NewTestKeyResolver(): KeyResolver {
    // console.log("key1", key1.did())
    // console.log("key2", key2.did())

    var keyTypeResolver: Map<string, any> = new Map()
    keyTypeResolver.set("Ed25519VerificationKey2018", EdKeypair)
    return {
        get: async (content: any): Promise<any> => {
            if (!content) {
                throw Error("content is empty")
            }
            if (content.type) {
                let keyFunc = keyTypeResolver.get(content.type)
                if (!keyFunc) {
                    throw Error(`method type is not registerd ${content.type}`)
                }
                let key = keyFunc.fromSecretKey(content.privateKeyBase64)
                return key
            }
            throw Error("content does not match universal wallet 2020 spec")
        }
    }
}


// console.log(indexedDB)
describe("pixi wallet for 3-link", () => {

    test("init", async () => {
        const walletConfig = { walletId: "storage1" }
        const wallet = walletFactory.build(walletConfig)
        await wallet.init(NewTestKeyResolver)
        expect(wallet.status).toBe(WalletStatus.Unlocked)
    })

    test("pixi wallet add and query", async () => {
        const walletConfig = { walletId: "storage2" }
        const wallet = walletFactory.build(walletConfig)
        await wallet.init(NewTestKeyResolver)
        let wcontent: WalletContent2020 = {
            id: "test1",
            name: "test1",
            type: "Object"
        }

        await wallet.add(wcontent)
        let byQuery: QueryContent2020 = {
            type: "Predicate",
            credentialQuery: (value: WalletContent2020) => {
                return value.id == wcontent.id
            }
        }
        let rcontent = await wallet.query(byQuery)
        expect(rcontent[0]).toEqual(wcontent)
    })

    test("lock and unlock", async () => {
        const walletConfig = { walletId: "storage2" }
        const wallet = walletFactory.build(walletConfig)
        await wallet.init(NewTestKeyResolver)
        let wcontent: WalletContent2020 = {
            id: "test1",
            name: "test1",
            type: "Object"

        }
        await wallet.add(wcontent)
        let byQuery: QueryContent2020 = {
            type: "Predicate",
            credentialQuery: (value: WalletContent2020) => {
                return value.id == wcontent.id
            }
        }
        let rcontent = await wallet.query(byQuery)
        expect(rcontent[0]).toEqual(wcontent)
        let password = "test"
        await wallet.lock(password)
        expect(wallet.getStatus()).toBe(WalletStatus.Locked)

        let wallet2 = walletFactory.build(walletConfig)
        await wallet2.init(NewTestKeyResolver)
        expect(wallet2.getStatus()).toBe(WalletStatus.Locked)
        let rcontent2 = await wallet2.query(byQuery)
        expect(rcontent2.length).toEqual(0)

        await wallet2.unlock(password)
        expect(wallet2.getStatus()).toBe(WalletStatus.Unlocked)
        let rcontent3 = await wallet2.query(byQuery)
        // console.log(rcontent3)
        expect(rcontent3[0]).toEqual(wcontent)
    })

    test("issue and verify", async () => {
        const walletConfig = { walletId: "storage3" }
        const wallet = walletFactory.build(walletConfig)
        await wallet.init(NewTestKeyResolver)
        let wcontent: WalletContent2020 = {
            id: "test1",
            name: "test1",
            type: "Object"

        }
        await wallet.add(wcontent)
        let byQuery: QueryContent2020 = {
            type: "Predicate",
            credentialQuery: (value: WalletContent2020) => {
                return value.id == wcontent.id
            }
        }
        let rcontent = await wallet.query(byQuery)
        expect(rcontent[0]).toEqual(wcontent)
        const keyContents1 = await encodeKey(key1.did(), key1)
        const keyContents2 = await encodeKey(key2.did(), key2)
        await wallet.add(keyContents1)
        await wallet.add(keyContents2)
        let token = await wallet.issue({ ...toSign, issuer: "did:key:z6Mkgd83FoGqvhtQ53sLKsJso6h3Xe8an3avaAnhuSg95Jsm" }, { iss: "did:key:z6Mkgd83FoGqvhtQ53sLKsJso6h3Xe8an3avaAnhuSg95Jsm" })
        expect(token).not.toBeUndefined()
        let result = await wallet.verify(token, toSignVerify)
        // console.log(result)
        expect(result.ok).toBeTruthy()
    })

    test("derive, verify and validate", async () => {
        const walletConfig = { walletId: "storage4" }
        const wallet = walletFactory.build(walletConfig)
        await wallet.init(NewTestKeyResolver)
        const keyContents1 = await encodeKey(key1.did(), key1)
        const keyContents2 = await encodeKey(key2.did(), key2)
        await wallet.add(keyContents1)
        await wallet.add(keyContents2)
        let cap1 = firstToSign("did:key:z6Mkgd83FoGqvhtQ53sLKsJso6h3Xe8an3avaAnhuSg95Jsm", "did:key:z6Mkp6hPmybgu8R4vP8xXd7wMv9K3aJMboK5qhrKaMXnFgVe")
        let token = await wallet.issue(cap1, { iss: "did:key:z6Mkgd83FoGqvhtQ53sLKsJso6h3Xe8an3avaAnhuSg95Jsm" })
        expect(token).not.toBeUndefined()
        let cap2 = toDerive("did:key:z6Mkp6hPmybgu8R4vP8xXd7wMv9K3aJMboK5qhrKaMXnFgVe", defaultAudience)
        let token2 = await wallet.derive(token, cap2, { iss: "did:key:z6Mkp6hPmybgu8R4vP8xXd7wMv9K3aJMboK5qhrKaMXnFgVe" })
        expect(token).not.toBeUndefined()
        let result = await wallet.verify(token2, toVerify("did:key:z6Mkgd83FoGqvhtQ53sLKsJso6h3Xe8an3avaAnhuSg95Jsm", defaultAudience))
        // console.log(result)
        expect(result.ok).toBeTruthy()

        let result2 = await wallet.validate(token2)
        // console.log(result2)
        expect(result2.payload.aud).toBe(defaultAudience)
    })

    test("custom key resolver", async () => {
        const walletConfig = { walletId: "storage5" }
        const wallet = walletFactory.build(walletConfig)
        await wallet.init(NewTestKeyResolver)
        let key = await EdKeypair.create({ exportable: true })
        let content = await encodeKey(key.did(), key)
        await wallet.add(content)
        let cap1 = firstToSign(key.did(), defaultAudience)
        let token = await wallet.issue(cap1, { iss: key.did() })
        expect(token).not.toBeUndefined()
    })

    test("query wallet", async () => {
        const walletConfig = { walletId: "storage6" }
        const wallet = walletFactory.build(walletConfig)
        await wallet.init(NewTestKeyResolver)
        let key = await EdKeypair.create({ exportable: true })
        let content = await encodeKey(key.did(), key)
        // console.log(content)
        await wallet.add(content)
        let cap1 = firstToSign(key.did(), defaultAudience)
        let token = await wallet.issue(cap1, { iss: key.did() })
        expect(token).not.toBeUndefined()

        let contentQuery: QueryContent2020 = {
            type: "Predicate",
            credentialQuery: (value: WalletContent2020) => {
                return value.type == "ucan"
            }
        }
        let ucans = await wallet.query(contentQuery)
        expect(ucans.length).toBe(1)

        cap1 = firstToSign(key.did(), defaultAudience)
        token = await wallet.issue(cap1, { iss: key.did() })

        ucans = await wallet.query(contentQuery)
        expect(ucans.length).toBe(2)
    })

})

function getTimestampInSeconds() {
    return Math.floor(Date.now() / 1000)
}
const toSign = {
    audience: "did:key:zDnaegJhvyDSdYubg2ZobTDiEwHsuLMvwSwp92o6e98Uov4fH", // recipient DID
    capabilities: [ // permissions for ucan
        {
            with: { scheme: "wnfs", hierPart: "//boris.fission.name/public/photos/" },
            can: { namespace: "wnfs", segments: ["OVERWRITE"] }
        },
        {
            with: { scheme: "wnfs", hierPart: "//boris.fission.name/private/6m-mLXYuXi5m6vxgRTfJ7k_xzbmpk7LeD3qYt0TM1M0" },
            can: { namespace: "wnfs", segments: ["APPEND"] }
        },
        {
            with: { scheme: "mailto", hierPart: "boris@fission.codes" },
            can: { namespace: "msg", segments: ["SEND"] },
            nb: { token: "header.payload.signature" }
        }
    ],
    // proofs: ["test.test.test"],
    facts: [{ "wtf": { "hello": "friend" } }],
    notBefore: getTimestampInSeconds(),
    expiration: getTimestampInSeconds() + 3600

}

const issuerDID = "did:key:z6Mkgd83FoGqvhtQ53sLKsJso6h3Xe8an3avaAnhuSg95Jsm"
const toSignVerify = {
    audience: toSign.audience, requiredCapabilities: [
        {
            capability: {
                with: { scheme: "mailto", hierPart: "boris@fission.codes" },
                can: { namespace: "msg", segments: ["SEND"] }
            },
            rootIssuer: issuerDID,
        }
    ]
}