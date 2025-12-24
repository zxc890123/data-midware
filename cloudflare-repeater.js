export default {
  async email(message, env) {
    const from = message.from
    const to = message.to.split('@')[0].replace(/^verify\+?/i, '')
    // Cloudflare Subaddressing: verify+<whatever>@domain
    // “+<whatever>”的部分只在worker中有效

    if (!to) {
      await message.setReject('User not found')
      return
    }

    const privateKey = await crypto.subtle.importKey(
      'pkcs8',
      Uint8Array.from(
        atob(
          env.RSA_PRIVATE_KEY_PEM
            .replace('-----BEGIN PRIVATE KEY-----', '')
            .replace('-----END PRIVATE KEY-----', '')
            .replace(/\s/g, '')
        ),
        c => c.charCodeAt(0)
      ),
      {
        name: 'RSA-PSS',
        hash: 'SHA-256'
      },
      false,
      ['sign']
    )

    const signature = await crypto.subtle.sign(
      {
        name: 'RSA-PSS',
        saltLength: 32
      },
      privateKey,
      new TextEncoder().encode(`${from}.${to}`)
    )

    const publicKey = await fetch(
      env.VERIFY_EMAIL_API.replace('/email/verify', '/crypto/public')
    ).then(res => res.json()).then(json => json.data).catch(err => {
      console.error(err)
      return null
    })

    if (!publicKey) {
      return
    }

    const cryptoRsa = new cryptoRSA(publicKey)
    const key = crypto.getRandomValues(new Uint8Array(136))
    const encryptedKey = await cryptoRsa.encrypt(key)
    const encryptedFrom = await new cryptoAES(key).encrypt(from)

    const req = new Request(
      env.VERIFY_EMAIL_API,
      {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-custom-encryption-key': encryptedKey
        },
        body: JSON.stringify({
          from_: encryptedFrom,
          to,
          signature: btoa(String.fromCharCode(...new Uint8Array(signature)))
        })
      }
    )
    await fetch(req)
  }
}

class cryptoRSA {
  constructor(pemString) {
    this.pemString = pemString
    this.publicKey = null
    this.keyPromise = this.initKey()
  }

  async initKey() {
    this.publicKey = await crypto.subtle.importKey(
      'spki',
      Uint8Array.from(
        atob(
          this.pemString
            .replace('-----BEGIN PUBLIC KEY-----', '')
            .replace('-----END PUBLIC KEY-----', '')
            .replace(/\s/g, '')
        ),
        c => c.charCodeAt(0)
      ),
      {
        name: 'RSA-OAEP',
        hash: 'SHA-256'
      },
      false,
      ['encrypt']
    )
  }

  async encrypt(u8Array) {
    await this.keyPromise
    const encrypted = await crypto.subtle.encrypt(
      { name: 'RSA-OAEP' },
      this.publicKey,
      u8Array
    )
    return btoa(String.fromCharCode(...new Uint8Array(encrypted)))
  }
}

class cryptoAES {
  constructor(u8Array) {
    this.key = null
    this.iv = null
    this.keyPromise = this.deriveKey(u8Array)
  }

  async deriveKey(u8Array) {
    let kdf = new Uint8Array()
    const counter = new Uint8Array(4)
    const counterView = new DataView(counter.buffer, counter.byteOffset, counter.byteLength)
    counterView.setUint32(0, 1)

    while (kdf.length < 64) {
      const data = new Uint8Array([...counter, ...u8Array])
      const hashBuffer = await crypto.subtle.digest('SHA-256', data)
      kdf = new Uint8Array([...kdf, ...new Uint8Array(hashBuffer)])
      counterView.setUint32(0, counterView.getUint32(0) + 1)
    }

    this.key = kdf.slice(-32)
    this.iv = kdf.slice(0, 16)
  }

  async encrypt(plainString) {
    await this.keyPromise
    const key = await crypto.subtle.importKey(
      'raw',
      this.key,
      { name: 'AES-CBC' },
      false,
      ['encrypt']
    )

    const encrypted = await crypto.subtle.encrypt(
      { name: 'AES-CBC', iv: this.iv },
      key,
      new TextEncoder().encode(plainString)
    )

    return btoa(String.fromCharCode(...new Uint8Array(encrypted)))
  }
}
