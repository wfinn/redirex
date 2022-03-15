# redirex

This tool generates bypasses for open redirects.  
Many of the bypasses apply for software other than browsers, but I recommend thorough fuzzing there.

1) find a redirect on your target
2) generate list of payloads for the domain
3) use Intruder, ffuf or headless browsers to test payloads
4) do manual testing for app specific payloads if the redirect seems unusual

```sh
go install github.com/wfinn/redirex@latest
redirex -t target.tld -a attacker.tld
redirex -h # to see all options
```

## Bypasses

- relative urls e.g. /%09/attacker.tld
- when all subdomains are allowed e.g. https://attacker.tld#.target.tld
- chars that don't really end the host part e.g. https://target.tld&.attacker.tld
- IP based bypasses e.g. //2130706433 (use -ip to change)
- unescaped dots in regexes e.g. https://wwwxtarget.tld
- unicode normalization after checking host e.g. attacker.com%EF%BC%8F.target.com -> attacker.com/.target.com
- ...

Many bypasses require that you have catch all DNS for your domain.  
Some bypasses only work in Safari.

This tool does not create all possible permutations, but aims to generate a good amount.

## Finding Redirects

Use [gau](https://github.com/lc/gau) and grep for =/ and =http to find a couple.

You can also use these parameters at login/logout.

```
?Redirect=/Redirect&RedirectUrl=/RedirectUrl&ReturnUrl=/ReturnUrl&Url=/Url&action=/action&action_url=/action_url&backurl=/backurl&burl=/burl&callback_url=/callback_url&checkout_url=/checkout_url&clickurl=/clickurl&continue=/continue&data=/data&dest=/dest&destination=/destination&desturl=/desturl&ext=/ext&forward=/forward&forward_url=/forward_url&go=/go&goto=/goto&image_url=/image_url&jump=/jump&jump_url=/jump_url&link=/link&linkAddress=/linkAddress&location=/location&login=/login&logout=/logout&next=/next&origin=/origin&originUrl=/originUrl&page=/page&pic=/pic&q=/q&qurl=/qurl&recurl=/recurl&redir=/redir&redirect=/redirect&redirect_uri=/redirect_uri&redirect_url=/redirect_url&request=/request&return=/return&returnTo=/returnTo&return_path=/return_path&return_to=/return_to&rit_url=/rit_url&rurl=/rurl&service=/service&sp_url=/sp_url&src=/src&success=/success&target=/target&u=/u&u1=/u1&uri=/uri&url=/url&view=/view
```

To test for for redirects that require full urls use `echo "params" | sed 's#=/#=https://TARGETDOMAIN/#g'`.

## Issues

- The order of the generated list is not ideal, manually tweaking it is recommended if you have many endpoints on the same target to get a hit faster.

---

Thanks to:
- @dbzer0 for https://github.com/dbzer0/ipfmt MIT License
- @jpillora for https://github.com/jpillora/go-tld MIT License
- @tomnomnom for https://github.com/tomnomnom/hacks/blob/master/unisub No License
