# End-User License Agreement (EULA)

This End-User License Agreement (EULA) governs the terms of use of the LocalStack software
platform and associated documentation (the "Software"). IF YOU DO NOT AGREE TO ALL OF THE TERMS
OF THIS EULA, DO NOT INSTALL, USE OR COPY THE SOFTWARE.

In the following, the maintainers of LocalStack are referred to as "LocalStack".

Note that this EULA only refers to the free, open source version of the Software, whereas any 
commercial offerings shall be covered in separate license agreements.

## Summary

* You must agree to all of the terms of this EULA to use this Software.
* If you agree to the terms of this EULA, you may use the Software for free and for any lawful purpose.
* This Software may automatically communicate with servers for three reasons: (1) to receive and 
install updates; (2) to send error reports; and (3) to send anonymized usage information. You can
view sample data to see what information is sent. See Privacy Notices further below for details.
* This Software is provided "as-is" with no warranties, and you agree that "LocalStack" is not
liable for anything you do with it.

## The Agreement

By downloading, installing, using, or copying the Software, you accept and agree to be bound by the 
terms of this EULA. If you do not agree to all of the terms of this EULA, you may not download, 
install, use or copy the Software.

## The License

This EULA entitles you to install as many copies of the Software as you want, and use the Software
for any lawful purpose consistent with this EULA. Your license to use the Software is expressly 
conditioned upon your agreement to all of the terms of this EULA. "LocalStack" reserves all
other rights not granted by this EULA.

You may use, extend, and redistribute this software under the terms of the Apache License 2.0
(see `LICENSE.txt`). Any third-party Open-Source Components included in this Software are subject
to the respective software licenses of those components.

To the extent there is conflict between the license terms covering the Open-Source Components and
this EULA, the terms of such licenses will apply in lieu of the terms of this EULA. To the extent
the terms of the licenses applicable to Open-Source Components prohibit any of the restrictions in
this Agreement with respect to such Open-Source Component, such restrictions will not apply to such
Open-Source Component.

# Privacy Notices

This Software may automatically communicate with servers for three reasons: (1) to receive and 
install updates; (2) to send error reports; and (3) to send anonymized usage information.
You can view sample data to see what information is sent (see below).

1. Automatic Software Updates. The Software may communicate with servers to determine whether
there are any patches, bug fixes, updates, upgrades or other modifications to improve the Software.
You agree that the Software may automatically install any such improvements to the Software on your
computer without providing any further notice or receiving any additional consent.

2. Error Reports. In order to help us improve the Software, when the Software encounters certain 
errors, it may automatically send some anonymized information that allows to analyze and debug the 
error.

3. Anonymized Usage Data. The Software collects anonymized data about your usage of the Software to 
help us make it even better. Details and examples are provided below.

**Please note:** Collecting of usage data has been introduced in version `0.7.0` and above. If you do
not want the Software to communicate with servers for updates, error reports, or anonymized usage
data, you may install versions `0.6.2` and below. Note, however, that these versions are no longer
actively maintained or improved.

## Examples of Anonymized Usage Data

The open source version of LocalStack may occasionally collect anonymized usage data for
processing at a central server. This usage data is fully anonymized, contains no personal
identifiable information whatsoever, and requires only very small amounts of network traffic
for transmission.

An example of usage data sent by the Software is provided in the JSON code listing below.
The field `e_t` specifies the event type, `t` specifies the current time, `m_id` is an
auto-generated machine identifier (which may be stored in a file on the local machine),
`p_id` is an auto-generated process identifier, and `p` is an optional payload field (which
is empty in this example).

```
{
    "e_t": "infra.start",
    "t": "2017-07-20T11:31:30",
    "m_id": "ed859e54",
    "p_id": "aa09ea33",
    "p": null
}
```

Please note that the above example is for illustration purposes only. The actual usage data
may vary and is subject to change.

# Disclaimers and Limitations on Liability

THE SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, AND NO WARRANTY, EITHER EXPRESS OR IMPLIED, IS GIVEN.
YOUR USE OF THE SOFTWARE IS AT YOUR SOLE RISK. "LocalStack" does not warrant that (i) the Software 
will meet your specific requirements; (ii) the Software is fully compatible with any particular 
platform; (iii) your use of the Software will be uninterrupted, timely, secure, or error-free; (iv) 
the results that may be obtained from the use of the Software will be accurate or reliable; (v) the 
quality of any products, services, information, or other material purchased or obtained by you through 
the Software will meet your expectations; or (vi) any errors in the Software will be corrected.

YOU EXPRESSLY UNDERSTAND AND AGREE THAT "LocalStack" SHALL NOT BE LIABLE FOR ANY DIRECT, INDIRECT, 
INCIDENTAL, SPECIAL, CONSEQUENTIAL OR EXEMPLARY DAMAGES, INCLUDING BUT NOT LIMITED TO, DAMAGES FOR 
LOSS OF PROFITS, GOODWILL, USE, DATA OR OTHER INTANGIBLE LOSSES (EVEN IF "LocalStack" HAS BEEN ADVISED 
OF THE POSSIBILITY OF SUCH DAMAGES) RELATED TO THE SOFTWARE, including, for example: (i) the use or 
the inability to use the Software; (ii) the cost of procurement of substitute goods and services 
resulting from any goods, data, information or services purchased or obtained or messages received or 
transactions entered into through or from the Software; (iii) unauthorized access to or alteration of 
your transmissions or data; (iv) statements or conduct of any third-party on the Software; (v) or any 
other matter relating to the Software.

"LocalStack" reserves the right at any time and from time to time to modify or discontinue, 
temporarily or permanently, the Software (or any part thereof) with or without notice. "LocalStack" 
shall not be liable to you or to any third-party for any modification, price change, suspension or 
discontinuance of the Software.

# Miscellanea

1. The failure of "LocalStack" to exercise or enforce any right or provision of this EULA shall not 
constitute a waiver of such right or provision.

2. This EULA constitutes the entire agreement between you and "LocalStack" and governs your use of the 
Software, superseding any prior agreements between you and "LocalStack" (including, but not limited 
to, any prior versions of the EULA).

3. Please send any questions about this EULA to info@localstack.cloud
