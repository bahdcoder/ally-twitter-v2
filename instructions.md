The package has been configured successfully!

Make sure to first define the mapping inside the `contracts/ally.ts` file as follows.

```ts
import { TwitterV2, TwitterV2Config } from '@bahdcoder/ally-twitter-v2/build/standalone'

declare module '@ioc:Adonis/Addons/Ally' {
  interface SocialProviders {
    // ... other mappings
    twitter_v2: {
      config: TwitterV2Config
      implementation: TwitterV2
    }
  }
}
```
