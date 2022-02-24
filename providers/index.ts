import type { ApplicationContract } from '@ioc:Adonis/Core/Application'

export default class TwitterV2Provider {
  constructor(protected app: ApplicationContract) {}

  public async boot() {
    const Ally = this.app.container.resolveBinding('Adonis/Addons/Ally')
    const { TwitterV2 } = await import('../src/TwitterV2')

    Ally.extend('twitter_v2', (_, __, config, ctx) => {
      return new TwitterV2(ctx, config)
    })
  }
}
