-- Table: concert_advisory.advisories

-- DROP TABLE IF EXISTS concert_advisory.advisories;

CREATE TABLE IF NOT EXISTS concert_advisory.advisories
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
    published_date timestamp with time zone,
    created_at timestamp with time zone DEFAULT now(),
    metadata jsonb,
    remediation_plan jsonb,
    CONSTRAINT advisories_pkey PRIMARY KEY (id),
    CONSTRAINT advisories_advisory_id_key UNIQUE (advisory_id)
)

TABLESPACE pg_default;

ALTER TABLE IF EXISTS concert_advisory.advisories
    OWNER to "12b12b08b15b95822f82407b";

-- Table: concert_advisory.advisories_products

-- DROP TABLE IF EXISTS concert_advisory.advisories_products;

CREATE TABLE IF NOT EXISTS concert_advisory.advisories_products
(
    advisory_id uuid NOT NULL,
    product_id uuid NOT NULL,
    field_data text COLLATE pg_catalog."default",
    CONSTRAINT advisories_products_pkey PRIMARY KEY (advisory_id, product_id),
    CONSTRAINT advisories_products_advisory_id_fkey FOREIGN KEY (advisory_id)
        REFERENCES concert_advisory.advisories (id) MATCH SIMPLE
        ON UPDATE NO ACTION
        ON DELETE CASCADE,
    CONSTRAINT advisories_products_product_id_fkey FOREIGN KEY (product_id)
        REFERENCES concert_advisory.product (id) MATCH SIMPLE
        ON UPDATE NO ACTION
        ON DELETE CASCADE
)

TABLESPACE pg_default;

ALTER TABLE IF EXISTS concert_advisory.advisories_products
    OWNER to "12b12b08b15b95822f82407b";
-- Table: concert_advisory.cves_advisories

-- DROP TABLE IF EXISTS concert_advisory.cves_advisories;

CREATE TABLE IF NOT EXISTS concert_advisory.cves_advisories
(
    cve_id text COLLATE pg_catalog."default" NOT NULL,
    advisory_id uuid NOT NULL,
    tags text[] COLLATE pg_catalog."default",
    CONSTRAINT cves_advisories_pkey PRIMARY KEY (cve_id, advisory_id),
    CONSTRAINT cves_advisories_advisory_id_fkey FOREIGN KEY (advisory_id)
        REFERENCES concert_advisory.advisories (id) MATCH SIMPLE
        ON UPDATE NO ACTION
        ON DELETE CASCADE,
    CONSTRAINT cves_advisories_cve_id_fkey FOREIGN KEY (cve_id)
        REFERENCES concert_advisory.vulnerabilities (cve_id) MATCH SIMPLE
        ON UPDATE NO ACTION
        ON DELETE CASCADE
)

TABLESPACE pg_default;

ALTER TABLE IF EXISTS concert_advisory.cves_advisories
    OWNER to "12b12b08b15b95822f82407b";

-- Table: concert_advisory.cves_packages

-- DROP TABLE IF EXISTS concert_advisory.cves_packages;

CREATE TABLE IF NOT EXISTS concert_advisory.cves_packages
(
    cve_id text COLLATE pg_catalog."default" NOT NULL,
    package_id uuid NOT NULL,
    CONSTRAINT cves_packages_pkey PRIMARY KEY (cve_id, package_id),
    CONSTRAINT cves_packages_cve_id_fkey FOREIGN KEY (cve_id)
        REFERENCES concert_advisory.vulnerabilities (cve_id) MATCH SIMPLE
        ON UPDATE NO ACTION
        ON DELETE CASCADE,
    CONSTRAINT cves_packages_package_id_fkey FOREIGN KEY (package_id)
        REFERENCES concert_advisory.packages (id) MATCH SIMPLE
        ON UPDATE NO ACTION
        ON DELETE CASCADE
)

TABLESPACE pg_default;

ALTER TABLE IF EXISTS concert_advisory.cves_packages
    OWNER to "12b12b08b15b95822f82407b";

-- Table: concert_advisory.licenses

-- DROP TABLE IF EXISTS concert_advisory.licenses;

CREATE TABLE IF NOT EXISTS concert_advisory.licenses
(
    id uuid NOT NULL DEFAULT gen_random_uuid(),
    name text COLLATE pg_catalog."default" NOT NULL,
    CONSTRAINT licenses_pkey PRIMARY KEY (id),
    CONSTRAINT licenses_name_key UNIQUE (name)
)

TABLESPACE pg_default;

ALTER TABLE IF EXISTS concert_advisory.licenses
    OWNER to "12b12b08b15b95822f82407b";

-- Table: concert_advisory.packages

-- DROP TABLE IF EXISTS concert_advisory.packages;

CREATE TABLE IF NOT EXISTS concert_advisory.packages
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

ALTER TABLE IF EXISTS concert_advisory.packages
    OWNER to "12b12b08b15b95822f82407b";

-- Table: concert_advisory.packages_licenses

-- DROP TABLE IF EXISTS concert_advisory.packages_licenses;

CREATE TABLE IF NOT EXISTS concert_advisory.packages_licenses
(
    package_id uuid NOT NULL,
    license_id uuid NOT NULL,
    CONSTRAINT packages_licenses_pkey PRIMARY KEY (package_id, license_id),
    CONSTRAINT packages_licenses_license_id_fkey FOREIGN KEY (license_id)
        REFERENCES concert_advisory.licenses (id) MATCH SIMPLE
        ON UPDATE NO ACTION
        ON DELETE CASCADE,
    CONSTRAINT packages_licenses_package_id_fkey FOREIGN KEY (package_id)
        REFERENCES concert_advisory.packages (id) MATCH SIMPLE
        ON UPDATE NO ACTION
        ON DELETE CASCADE
)

TABLESPACE pg_default;

ALTER TABLE IF EXISTS concert_advisory.packages_licenses
    OWNER to "12b12b08b15b95822f82407b";

-- Table: concert_advisory.product

-- DROP TABLE IF EXISTS concert_advisory.product;

CREATE TABLE IF NOT EXISTS concert_advisory.product
(
    id uuid NOT NULL DEFAULT gen_random_uuid(),
    name text COLLATE pg_catalog."default" NOT NULL,
    vendor text COLLATE pg_catalog."default",
    product_family text COLLATE pg_catalog."default",
    version text COLLATE pg_catalog."default",
    release_date timestamp without time zone,
    eol_date timestamp without time zone,
    extended_support boolean DEFAULT false,
    CONSTRAINT product_pkey PRIMARY KEY (id),
    CONSTRAINT unique_product_version UNIQUE (name, vendor, product_family, version)
)

TABLESPACE pg_default;

ALTER TABLE IF EXISTS concert_advisory.product
    OWNER to "12b12b08b15b95822f82407b";

-- Table: concert_advisory.product_dependency

-- DROP TABLE IF EXISTS concert_advisory.product_dependency;

CREATE TABLE IF NOT EXISTS concert_advisory.product_dependency
(
    parent_product_id uuid NOT NULL,
    dependency_product_id uuid NOT NULL,
    dependent_type text COLLATE pg_catalog."default",
    supported_version_range text COLLATE pg_catalog."default",
    CONSTRAINT product_dependency_pkey PRIMARY KEY (parent_product_id, dependency_product_id),
    CONSTRAINT product_dependency_dependency_product_id_fkey FOREIGN KEY (dependency_product_id)
        REFERENCES concert_advisory.product (id) MATCH SIMPLE
        ON UPDATE NO ACTION
        ON DELETE CASCADE,
    CONSTRAINT product_dependency_parent_product_id_fkey FOREIGN KEY (parent_product_id)
        REFERENCES concert_advisory.product (id) MATCH SIMPLE
        ON UPDATE NO ACTION
        ON DELETE CASCADE
)

TABLESPACE pg_default;

ALTER TABLE IF EXISTS concert_advisory.product_dependency
    OWNER to "12b12b08b15b95822f82407b";

-- Table: concert_advisory.product_release

-- DROP TABLE IF EXISTS concert_advisory.product_release;

CREATE TABLE IF NOT EXISTS concert_advisory.product_release
(
    release_id uuid NOT NULL DEFAULT gen_random_uuid(),
    product_id uuid NOT NULL,
    full_version text[] COLLATE pg_catalog."default",
    major_version integer,
    minor_version integer,
    patch_version integer,
    release_date timestamp with time zone,
    eol_date timestamp with time zone,
    extended_support boolean DEFAULT false,
    CONSTRAINT product_release_pkey PRIMARY KEY (release_id),
    CONSTRAINT product_release_product_id_fkey FOREIGN KEY (product_id)
        REFERENCES concert_advisory.product (id) MATCH SIMPLE
        ON UPDATE NO ACTION
        ON DELETE CASCADE
)

TABLESPACE pg_default;

ALTER TABLE IF EXISTS concert_advisory.product_release
    OWNER to "12b12b08b15b95822f82407b";

-- Table: concert_advisory.vulnerabilities

-- DROP TABLE IF EXISTS concert_advisory.vulnerabilities;

CREATE TABLE IF NOT EXISTS concert_advisory.vulnerabilities
(
    cve_id text COLLATE pg_catalog."default" NOT NULL,
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
    is_zero_day boolean DEFAULT false,
    is_exploitable boolean DEFAULT false,
    is_patch_available boolean DEFAULT false,
    cwe_references jsonb,
    cpe_references jsonb,
    reference_links jsonb,
    "raw" jsonb,
    tags text[] COLLATE pg_catalog."default",
    published_date timestamp with time zone,
    modified_date timestamp with time zone,
    last_modified_date timestamp with time zone,
    CONSTRAINT vulnerabilities_pkey PRIMARY KEY (cve_id)
)

TABLESPACE pg_default;

ALTER TABLE IF EXISTS concert_advisory.vulnerabilities
    OWNER to "12b12b08b15b95822f82407b";
