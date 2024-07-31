#!/usr/bin/env -S deno run --allow-net

const params = /\s*([^=\s]+)\s*=\s*(?:([^",]*)|"((?:[^"]|\\")*)")\s*,/g;
const schemes = new RegExp(String.raw`(\S+)\s+((?:${params.source})*)`, "g");

const parseWwwAuthenticate = (header) =>
  Object.fromEntries(
    Array.from(
      `${header} ,`.matchAll(schemes),
      ([_, authScheme, authParams]) => [
        authScheme.toLowerCase(),
        Object.fromEntries(
          Array.from(
            authParams.matchAll(params),
            ([_, key, valueRaw, valueQuoted]) => [
              key.toLowerCase(),
              valueRaw ?? valueQuoted.replaceAll('\\"', '"'),
            ]
          )
        ),
      ]
    )
  );

class Reference {
  constructor(reference) {
    const [_, domain, path, tag, digest] = reference.match(
      /^([^/]*\.[^/*]*)\/(.*?)(?::(.*?))?(?:@(.*?))?$/
    );
    this.domain = domain;
    this.path = path;
    this.tag = tag ?? (digest ? "" : "latest");
    this.digest = digest;
  }
  getUrl(type = "manifests") {
    return `https://${this.domain}/v2/${this.path}/${type}/${
      this.digest ?? this.tag
    }`;
  }
  toString() {
    return `${this.domain}/${this.path}${this.tag ? `:${this.tag}` : ""}${
      this.digest ? `@${this.digest}` : ""
    }`;
  }
}

class Client {
  auth;
  username;
  password;

  async getToken(res, username = this.username, password = this.password) {
    const {
      bearer: { realm, scope, service },
    } = parseWwwAuthenticate(res.headers.get("www-authenticate"));
    const auth = await (
      await fetch(`${realm}?${new URLSearchParams({ scope, service })}`, {
        headers: {
          ...(username && {
            authorization: `basic ${btoa(`${username}:${password}`)}`,
          }),
        },
      })
    ).json();
    return `Bearer ${auth.access_token ?? auth.token}`;
  }
  async fetch(reference, type = "blobs", opts = {}, { auth } = {}) {
    const res = await fetch(reference.getUrl(type), {
      ...opts,
      headers: {
        ...(auth ?? this.auth),
        ...opts.headers,
      },
    });
    if (res.status === 401 && !auth) {
      const auth = (this.auth = { authorization: await this.getToken(res) });
      return this.fetch(reference, type, opts, { auth });
    }
    return res;
  }
  async fetchManifest(reference, opts = {}) {
    return await (
      await this.fetch(reference, "manifests", {
        headers: {
          accept: [
            "application/vnd.oci.image.manifest.v1+json",
            "application/vnd.oci.image.index.v1+json",
            "application/vnd.docker.distribution.manifest.v2+json",
            "application/vnd.docker.distribution.manifest.list.v2+json",
          ],
        },
        ...opts,
      })
    ).json();
  }
}

const client = new Client();

Deno.serve(async (/**@type{Request}*/ req) => {
  const url = new URL(req.url);
  const reference = new Reference(url.pathname.slice(1));
  const { type, layer = 0 } = Object.fromEntries(url.searchParams);
  if (type === "blob") {
    const res = await client.fetch(reference, "blobs", { redirect: "manual" });
    return res;
  } else {
    const res = await client.fetchManifest(reference);
    reference.digest = res.layers.at(layer).digest;
    url.pathname = `/${reference}`;
    url.searchParams.set("type", "blob");
    return Response.redirect(url);
  }
});
