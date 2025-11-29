script 2(context builder)
    input:
    product_name : openvpn <- search keyword so be specific (laravel framework / etc)
    cve_id: CVE-2023-XXXX
    version_of_interest: 1.2.3
    

    
    1. check nuclei for exploit [static] [git clone nuclei templates if not exis and just grep]
       1. if exist: 
          1. exploit_array append {"details" ...}
          2. refrence_links append [refrences]
    2. github lookup : goto advisories
          1. https://github.com/advisories?query=CVE-2023-43795+geoserver
          2. if found:
              1. refrence_links append [refrences]
              2. get description
              3. get severity
           3. not found:
              1. get description and severity from https://github.com/CVEProject/cvelistV5 [clone if not exist and just grep]
    3. github search
       1. search for "CVE-2023-43795 geoserver" on github  and filettpe not yaml,json
    4. x.com : can do 
       1. search for "CVE-2023-43795 geoserver" on x.com
    5. their official website
       1. ai crawler

    parse refrence links from githb ub advisories page
        if refrence link is https://github.com/\w+/\w+/commit/\w+ or 
        https://github.com/\w+/\w+/pull/\d+ 
        then just do `curl link.diff` and get the diff <- 

        if ref link is 200 OK without redirect (and if with redirect have a number in path)
        then goto link and get its main content 

        else ignore

        now all this get little bit summaized and converted into a context to be fed in future

    6. x.com lookup (top 5 sort by likes/retweets)
       1. has link ->
          1. same refrence link parsing as above
       2. no link -> 
          summarize and take content
   
    7. official website lookup
       i have this , just keep interface/ demo code for this, i ll add late


T1: 
{
    "ID": "unique_context_id_12345",
    "CVE_ID": "CVE-2023-XXXX",
    "Product_Name": "openvpn",
    "Version_of_Interest": "1.2.3",
    "Description": "Detailed description of the vulnerability...",
    "Severity": "High",
    "Exploit_Details": [
        {
            "Exploit_Type": "Nuclei",
            "full_template": "yaml content of the nuclei template",
        }
    ],
    "Reference_Links": [
        from nuclei,
        from github advisories,
        from x.com
    ]
}

T2: reference
    ref_id: T1.ID
    raw_data: {
        link: data
    }
    summarized: {
        link: data
    }
