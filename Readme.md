# pixi wallet 

implementation of universal wallet 2020 spec

## usage 

create
.npmrc
```
@mkabanau:registry=https://npm.pkg.github.com
@pixi-wallet:registry=https://npm.pkg.github.com
//npm.pkg.github.com/:_authToken=${NODE_AUTH_TOKEN}
always-auth=true
```

```
npm i @pixi-wallet/wallet
```

usage
```ts
        const walletConfig = { walletId: "storage1" } // create indexdb storage
        const wallet = walletFactory.build(walletConfig) //build wallet object
        // NewTestKeyResolver implements key resolution
        await wallet.init(NewTestKeyResolver) // inits async resources.
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
        await wallet.add(keyContents1)

        let token = await wallet.issue({ ...toSign, issuer: "did:key:z6Mkgd83FoGqvhtQ53sLKsJso6h3Xe8an3avaAnhuSg95Jsm" }, { iss: "did:key:z6Mkgd83FoGqvhtQ53sLKsJso6h3Xe8an3avaAnhuSg95Jsm" })
        expect(token).not.toBeUndefined()
        
        let result = await wallet.verify(token, toSignVerify)

        let contentQuery: QueryContent2020 = {
            type: "Predicate",
            credentialQuery: (value: WalletContent2020) => {
                return value.type == "ucan"
            }
        }
        
        let ucans = await wallet.query(contentQuery)
        expect(ucans.length).toBe(1)

```

check test for more examples. 