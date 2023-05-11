import { YJSStorageProvider, IStorage } from "@pixi-wallet/yjs-storage"
import * as Factory from 'factory.ts'

import { seedToId, passwordToKey, lockContent, unlockContents, exportContentsAsCredential, contentsFromEncryptedWalletCredential, WalletContent2020 } from '@pixi-wallet/components'

import { CapabilityService, capabilityPlugin, encode } from "@pixi-wallet/ucan-plugin"
import { EdKeypair} from "@mkabanau/default-plugins"

export enum WalletStatus {
    Locked = "LOCKED",
    Unlocked = "UNLOCKED"
}


interface Options {
    iss: string
    [name: string]: any
}

export interface CapabilityResolver {
    ByCID: string
    ByAudienence: string
    ByIssuer: string
}

// export interface StoreI {
//     // add(ucan: Ucan): Promise<void>;
//     getByAudience(audience: string): Ucan[];
//     findByAudience(audience: string, predicate: (ucan: Ucan) => boolean): Ucan | null;
//     findWithCapability(audience: string, requiredCapability: Capability, requiredIssuer: string): Iterable<DelegationChain>;
// }

export interface KeyResolver {
    get: (keyId: any) => Promise<any>;
}


export interface Capability {
    capabilityProvider: CapabilityService;
    verify: (token: any, opts: any) => Promise<any>;
    issue: (cap: any, opts: Options) => Promise<any>;
    prove: (cap: any, opts: any) => Promise<any>;
    derive: (proof: any, cap: any, opts: any) => Promise<any>;
    validate: (cap:any, opts?:any) => Promise<any>;
}

export interface Wallet {
    status: WalletStatus;
    walletId: string;
    contents: IStorage;
    keyResolver:KeyResolver;
    init: (keyResolver:()=>KeyResolver) => Promise<void>;
    getStatus: () => WalletStatus;
    seedToId: (seed: Uint8Array) => Promise<string>;
    passwordToKey: (password: string) => Promise<Uint8Array>;
    add: (content: any) => Promise<void>;
    query: (opts: any) => Promise<any>;
    remove: (contentId: string) => Promise<any>;
    lock: (password: string) => Promise<void>;
    unlock: (password: string) => Promise<void>;
    export: (password: string) => Promise<any>;
    import: (encryptedWalletCredential: any, password: string) => Promise<Wallet>;
}

interface Helpers {
    getKeyFromStorage: (did:string) => Promise<any>
}

interface PixiWallet extends Wallet, Capability, Helpers { }

var walletDefaults = {
    status: WalletStatus.Unlocked,
    walletId: "test-storage",
    contents: undefined,
    capabilityProvider: undefined,
    keyResolver: undefined,
    init: async function (keyResolver: ()=>KeyResolver): Promise<void> {
        (this as Wallet).contents = new YJSStorageProvider((this as Wallet).walletId);
        await (this as Wallet).contents.IsReady();
        (this as PixiWallet).capabilityProvider = capabilityPlugin.build();
        (this as Wallet).keyResolver = keyResolver()
        return
    },
    getStatus: function (): WalletStatus {
        let walletId = (this as Wallet).walletId;
        let encrypteContents = localStorage.getItem(walletId);
        // console.log(encrypteContents)
        if (encrypteContents) {
            (this as Wallet).status = WalletStatus.Locked;
        }
        return (this as Wallet).status
    },
    seedToId,
    passwordToKey,
    add: async function (content: any): Promise<void> {
        await (this as Wallet).contents.Put(content);
        return this;
    },
    query: function (opts: any): Promise<any> {
        return (this as Wallet).contents.Query(opts);
    },
    remove: function (contentId: string): Promise<any> {
        return (this as Wallet).contents.Remove(contentId);
    },
    lock: async function (password: string): Promise<void> {
        let contents = await (this as Wallet).contents.Export()
        let encryptedContents = await lockContent(
            password,
            { contents }
        );
        let walletId = (this as Wallet).walletId;
        localStorage.setItem(walletId, JSON.stringify(encryptedContents));
        await (this as Wallet).contents.Clear();
        (this as Wallet).status = WalletStatus.Locked;
        return;
    },
    unlock: async function (password: string): Promise<void> {
        let walletId = (this as Wallet).walletId;
        let encrypteContents = localStorage.getItem(walletId)
        if (!encrypteContents) {
            throw Error(`nothing to unlock for walletId ${walletId}`)
        }
        let contents = await unlockContents(
            password,
            JSON.parse(encrypteContents)
        );
        await (this as Wallet).contents.Import(contents.contents);

        (this as Wallet).status = WalletStatus.Unlocked;
        localStorage.removeItem(walletId)
        return;
    },
    export: async function (password: string): Promise<any> {
        let contents = await (this as Wallet).contents.Export()
        return exportContentsAsCredential(password, contents);
    },
    import: async function (
        encryptedWalletCredential: any,
        password: string
    ): Promise<any> {
        let contents = await contentsFromEncryptedWalletCredential(
            password,
            encryptedWalletCredential
        );
        await (this as Wallet).contents.Import(contents)
        this.status = WalletStatus.Unlocked;
        return this;
    },
    verify: async function (token:any, opts:any): Promise<any> {
        return (this as PixiWallet).capabilityProvider.verify(token, opts)
    },
    validate: async function (token:any, opts?:any): Promise<any> {
        return (this as PixiWallet).capabilityProvider.validate(token, opts)
    },
    getKeyFromStorage: async function getKeyFromStorage(did:string):Promise<any> {
        let content = await (this as Wallet).contents.Get(did)
        let key = await ((this as Wallet).keyResolver as KeyResolver).get(content)
        return key
    },

    issue: async function (cap:any, opts:any): Promise<any> {
        let key = await (this as Helpers).getKeyFromStorage(opts.iss)
        if (!key) {
            throw Error(`key is not found ${opts.iss}`)
        }
        let capability = await (this as PixiWallet).capabilityProvider.issue(cap, {iss:(key as EdKeypair)});
        let encodedCap = encode(capability);
        (this as Wallet).contents.Put({"id":encodedCap, type:"ucan"});
        return encodedCap;
    },
    prove: async function (cap:any, opts:any): Promise<any> {
        let key = await (this as Helpers).getKeyFromStorage(opts.iss)
        if (!key) {
            throw Error(`key is not found ${opts.iss}`)
        }
        let capability = await (this as PixiWallet).capabilityProvider.prove(cap, {iss:(key as EdKeypair), aud: opts.aud});
        let encodedCap = encode(capability);
        (this as Wallet).contents.Put({"id":encodedCap, type:"ucan"});
        return encodedCap;
    },
    derive: async function (token:any, cap:any, opts:any): Promise<any> {
        let key = await (this as Helpers).getKeyFromStorage(opts.iss)
        if (!key) {
            throw Error(`key is not found ${opts.iss}`)
        }
        let capability = await (this as PixiWallet).capabilityProvider.derive(token, cap, {iss:(key as EdKeypair), aud:opts.aud});
        let encodedCap = encode(capability);
        (this as Wallet).contents.Put({"id":encodedCap, type:"ucan"});
        return encodedCap;
    },

};

const walletFactory = Factory.Sync.makeFactoryWithRequired<PixiWallet, "walletId">(walletDefaults);

export { PixiWallet, walletFactory, walletDefaults };