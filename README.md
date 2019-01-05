# idp

**note:** this is very much experimental softawre. it is not stable nor secure. don't use it!

This is me experimenting with writing my own identity provider.

![tweet about me getting caremad about identity providers](http://cdn.lstoll.net/screen/Lincoln_Stoll_on_Twitter_Getting_kinda_caremad_about_Identity_Providers_as_one_typically_does_on_Christmas_Eve._2019-01-05_11-23-52.png)

![tweet about me writing my own](http://cdn.lstoll.net/screen/Lincoln_Stoll_on_Twitter_Update_Im_pulling_my_own_together_its_gonna_be_the_best._2019-01-05_11-24-28.png)

The goals are:
* OIDC and SAML support
* Auth using webauthn
* Ways to authenticate workloads
* Playground to make experimenting on this stuff easy

Basically this takes [dex](github.com/dexidp/dex) and [crewjam/saml](crewjam/saml) and treats them as libraries behind a common, simple interface. It's then gonna have some other bits build around it.

There's a tester saml/oidc client in cmd/example-client, and a simple implementation of a full idp in cmd/example-idp.

See [Issues](/../../issues) for the closest thign we have to a roadmap.