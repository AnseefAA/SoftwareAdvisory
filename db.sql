-- Table: public.advisory

-- DROP TABLE IF EXISTS public.advisory;

CREATE TABLE IF NOT EXISTS public.advisory
(
    id uuid NOT NULL DEFAULT gen_random_uuid(),
    advisory_id text COLLATE pg_catalog."default" NOT NULL,
    vendor text COLLATE pg_catalog."default",
    title text COLLATE pg_catalog."default",
    aggregate_severity text COLLATE pg_catalog."default",
    advisory_url text COLLATE pg_catalog."default",
    csaf_version text COLLATE pg_catalog."default",
    advisory_type text COLLATE pg_catalog."default",
    advisory_status text COLLATE pg_catalog."default",
    tlp_label text COLLATE pg_catalog."default",
    supersedes text COLLATE pg_catalog."default",
    patch_release_date timestamp with time zone,
    workaround_available boolean DEFAULT false,
    patch_stability text COLLATE pg_catalog."default",
    known_regressions boolean DEFAULT false,
    published_date timestamp with time zone,
    created_at timestamp with time zone DEFAULT now(),
    metadata jsonb,
    remediation_plan jsonb,
    CONSTRAINT advisory_pkey PRIMARY KEY (id),
    CONSTRAINT advisory_advisory_id_key UNIQUE (advisory_id)
)

TABLESPACE pg_default;

ALTER TABLE IF EXISTS public.advisory
    OWNER to "12b12b08b15b95822f82407b";

-- Table: public.advisories_products

-- DROP TABLE IF EXISTS public.advisories_products;

CREATE TABLE IF NOT EXISTS public.advisories_products
(
    advisory_id uuid NOT NULL,
    product_id uuid NOT NULL,
    field_data text COLLATE pg_catalog."default",
    CONSTRAINT advisories_products_pkey PRIMARY KEY (advisory_id, product_id),
    CONSTRAINT advisories_products_advisory_id_fkey FOREIGN KEY (advisory_id)
        REFERENCES public.advisory (id) MATCH SIMPLE
        ON UPDATE NO ACTION
        ON DELETE CASCADE,
    CONSTRAINT advisories_products_product_id_fkey FOREIGN KEY (product_id)
        REFERENCES public.product (id) MATCH SIMPLE
        ON UPDATE NO ACTION
        ON DELETE CASCADE
)

TABLESPACE pg_default;

ALTER TABLE IF EXISTS public.advisories_products
    OWNER to "12b12b08b15b95822f82407b";
-- Index: idx_adv_prod_adv

-- DROP INDEX IF EXISTS public.idx_adv_prod_adv;

CREATE INDEX IF NOT EXISTS idx_adv_prod_adv
    ON public.advisories_products USING btree
    (advisory_id ASC NULLS LAST)
    TABLESPACE pg_default;
-- Index: idx_adv_prod_prod

-- DROP INDEX IF EXISTS public.idx_adv_prod_prod;

CREATE INDEX IF NOT EXISTS idx_adv_prod_prod
    ON public.advisories_products USING btree
    (product_id ASC NULLS LAST)
    TABLESPACE pg_default;

-- Table: public.licenses

-- DROP TABLE IF EXISTS public.licenses;

CREATE TABLE IF NOT EXISTS public.licenses
(
    id uuid NOT NULL DEFAULT gen_random_uuid(),
    name text COLLATE pg_catalog."default" NOT NULL,
    CONSTRAINT licenses_pkey PRIMARY KEY (id),
    CONSTRAINT licenses_name_key UNIQUE (name)
)

TABLESPACE pg_default;

ALTER TABLE IF EXISTS public.licenses
    OWNER to "12b12b08b15b95822f82407b";

-- Table: public.packages

-- DROP TABLE IF EXISTS public.packages;

CREATE TABLE IF NOT EXISTS public.packages
(
    id uuid NOT NULL DEFAULT gen_random_uuid(),
    name text COLLATE pg_catalog."default" NOT NULL,
    version text COLLATE pg_catalog."default",
    ecosystem text COLLATE pg_catalog."default",
    description text COLLATE pg_catalog."default",
    published_at timestamp without time zone,
    CONSTRAINT packages_pkey PRIMARY KEY (id),
    CONSTRAINT unique_package UNIQUE (name, version, ecosystem)
)

TABLESPACE pg_default;

ALTER TABLE IF EXISTS public.packages
    OWNER to "12b12b08b15b95822f82407b";

-- Table: public.packages_licenses

-- DROP TABLE IF EXISTS public.packages_licenses;

CREATE TABLE IF NOT EXISTS public.packages_licenses
(
    package_id uuid NOT NULL,
    license_id uuid NOT NULL,
    CONSTRAINT packages_licenses_pkey PRIMARY KEY (package_id, license_id),
    CONSTRAINT packages_licenses_license_id_fkey FOREIGN KEY (license_id)
        REFERENCES public.licenses (id) MATCH SIMPLE
        ON UPDATE NO ACTION
        ON DELETE CASCADE,
    CONSTRAINT packages_licenses_package_id_fkey FOREIGN KEY (package_id)
        REFERENCES public.packages (id) MATCH SIMPLE
        ON UPDATE NO ACTION
        ON DELETE CASCADE
)

TABLESPACE pg_default;

ALTER TABLE IF EXISTS public.packages_licenses
    OWNER to "12b12b08b15b95822f82407b";

-- Table: public.product

-- DROP TABLE IF EXISTS public.product;

CREATE TABLE IF NOT EXISTS public.product
(
    id uuid NOT NULL DEFAULT gen_random_uuid(),
    name text COLLATE pg_catalog."default" NOT NULL,
    vendor text COLLATE pg_catalog."default",
    product_family text COLLATE pg_catalog."default",
    version text COLLATE pg_catalog."default",
    product_type text COLLATE pg_catalog."default",
    architecture text COLLATE pg_catalog."default",
    support_level text COLLATE pg_catalog."default",
    release_date timestamp without time zone,
    eol_date timestamp without time zone,
    extended_support boolean DEFAULT false,
    CONSTRAINT product_pkey PRIMARY KEY (id),
    CONSTRAINT unique_product_version UNIQUE (name, vendor, product_family, version)
)

TABLESPACE pg_default;

ALTER TABLE IF EXISTS public.product
    OWNER to "12b12b08b15b95822f82407b";

-- Table: public.product_dependency

-- DROP TABLE IF EXISTS public.product_dependency;

CREATE TABLE IF NOT EXISTS public.product_dependency
(
    parent_product_id uuid NOT NULL,
    dependency_product_id uuid NOT NULL,
    dependent_type text COLLATE pg_catalog."default",
    supported_version_range text COLLATE pg_catalog."default",
    certification_status text COLLATE pg_catalog."default",
    certification_source text COLLATE pg_catalog."default",
    dependency_criticality text COLLATE pg_catalog."default",
    CONSTRAINT product_dependency_pkey PRIMARY KEY (parent_product_id, dependency_product_id),
    CONSTRAINT product_dependency_dependency_product_id_fkey FOREIGN KEY (dependency_product_id)
        REFERENCES public.product (id) MATCH SIMPLE
        ON UPDATE NO ACTION
        ON DELETE CASCADE,
    CONSTRAINT product_dependency_parent_product_id_fkey FOREIGN KEY (parent_product_id)
        REFERENCES public.product (id) MATCH SIMPLE
        ON UPDATE NO ACTION
        ON DELETE CASCADE
)

TABLESPACE pg_default;

ALTER TABLE IF EXISTS public.product_dependency
    OWNER to "12b12b08b15b95822f82407b";

-- Table: public.product_packages

-- DROP TABLE IF EXISTS public.product_packages;

CREATE TABLE IF NOT EXISTS public.product_packages
(
    product_id uuid NOT NULL,
    package_id uuid NOT NULL,
    CONSTRAINT product_packages_pkey PRIMARY KEY (product_id, package_id),
    CONSTRAINT product_packages_package_id_fkey FOREIGN KEY (package_id)
        REFERENCES public.packages (id) MATCH SIMPLE
        ON UPDATE NO ACTION
        ON DELETE CASCADE,
    CONSTRAINT product_packages_product_id_fkey FOREIGN KEY (product_id)
        REFERENCES public.product (id) MATCH SIMPLE
        ON UPDATE NO ACTION
        ON DELETE CASCADE
)

TABLESPACE pg_default;

ALTER TABLE IF EXISTS public.product_packages
    OWNER to "12b12b08b15b95822f82407b";

-- Table: public.vulnerability

-- DROP TABLE IF EXISTS public.vulnerability;

CREATE TABLE IF NOT EXISTS public.vulnerability
(
    id text COLLATE pg_catalog."default" NOT NULL,
    title text COLLATE pg_catalog."default",
    description text COLLATE pg_catalog."default",
    latest_vector_string text COLLATE pg_catalog."default",
    latest_severity text COLLATE pg_catalog."default",
    latest_cvss_score double precision,
    cvss_metrics jsonb,
    source_identifier text COLLATE pg_catalog."default",
    vulnerability_status text COLLATE pg_catalog."default",
    exploitability_score double precision,
    impact_score double precision,
    epss_score double precision,
    kev_listed boolean DEFAULT false,
    exploit_poc_available boolean DEFAULT false,
    ransomware_association boolean DEFAULT false,
    exploit_maturity text COLLATE pg_catalog."default",
    attack_vector text COLLATE pg_catalog."default",
    privileges_required text COLLATE pg_catalog."default",
    is_zero_day boolean DEFAULT false,
    is_exploitable boolean DEFAULT false,
    is_patch_available boolean DEFAULT false,
    cwe_references jsonb,
    cpe_references jsonb,
    reference_links jsonb,
    tags text[] COLLATE pg_catalog."default",
    published_date timestamp with time zone,
    modified_date timestamp with time zone,
    last_modified_date timestamp with time zone,
    "raw" jsonb,
    CONSTRAINT vulnerabilities_pkey PRIMARY KEY (id)
)

TABLESPACE pg_default;

ALTER TABLE IF EXISTS public.vulnerability
    OWNER to "12b12b08b15b95822f82407b";

-- Table: public.vulnerability_advisories

-- DROP TABLE IF EXISTS public.vulnerability_advisories;

CREATE TABLE IF NOT EXISTS public.vulnerability_advisories
(
    vulnerability_id text COLLATE pg_catalog."default" NOT NULL,
    advisory_id uuid NOT NULL,
    tags text[] COLLATE pg_catalog."default",
    CONSTRAINT cves_advisories_pkey PRIMARY KEY (vulnerability_id, advisory_id),
    CONSTRAINT cves_advisories_advisory_id_fkey FOREIGN KEY (advisory_id)
        REFERENCES public.advisory (id) MATCH SIMPLE
        ON UPDATE NO ACTION
        ON DELETE CASCADE,
    CONSTRAINT cves_advisories_cve_id_fkey FOREIGN KEY (vulnerability_id)
        REFERENCES public.vulnerability (id) MATCH SIMPLE
        ON UPDATE NO ACTION
        ON DELETE CASCADE
)

TABLESPACE pg_default;

ALTER TABLE IF EXISTS public.vulnerability_advisories
    OWNER to "12b12b08b15b95822f82407b";
-- Index: idx_cves_adv_adv

-- DROP INDEX IF EXISTS public.idx_cves_adv_adv;

CREATE INDEX IF NOT EXISTS idx_cves_adv_adv
    ON public.vulnerability_advisories USING btree
    (advisory_id ASC NULLS LAST)
    TABLESPACE pg_default;
-- Index: idx_cves_adv_cve

-- DROP INDEX IF EXISTS public.idx_cves_adv_cve;

CREATE INDEX IF NOT EXISTS idx_cves_adv_cve
    ON public.vulnerability_advisories USING btree
    (vulnerability_id COLLATE pg_catalog."default" ASC NULLS LAST)
    TABLESPACE pg_default;

-- Table: public.vulnerability_packages

-- DROP TABLE IF EXISTS public.vulnerability_packages;

CREATE TABLE IF NOT EXISTS public.vulnerability_packages
(
    vulnerability_id text COLLATE pg_catalog."default" NOT NULL,
    package_id uuid NOT NULL,
    status text COLLATE pg_catalog."default",
    CONSTRAINT cves_packages_pkey PRIMARY KEY (vulnerability_id, package_id),
    CONSTRAINT cves_packages_cve_id_fkey FOREIGN KEY (vulnerability_id)
        REFERENCES public.vulnerability (id) MATCH SIMPLE
        ON UPDATE NO ACTION
        ON DELETE CASCADE,
    CONSTRAINT cves_packages_package_id_fkey FOREIGN KEY (package_id)
        REFERENCES public.packages (id) MATCH SIMPLE
        ON UPDATE NO ACTION
        ON DELETE CASCADE
)

TABLESPACE pg_default;

ALTER TABLE IF EXISTS public.vulnerability_packages
    OWNER to "12b12b08b15b95822f82407b";