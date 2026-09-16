# Pluto ♇

## Overview

*Pluto* is a research tool for measuring URL lifespan, link rot, and web content change. It reconstructs a URL’s history by checking the live web and every compatible archive in our [web-archive.txt](https://github.com/overbrowsing/web-archive.txt) registry, then classifies it from S0 (alive and unchanged) to S4 (confirmed disappearance). Findings are corroborated across archives rather than trusted from a single source, following the Roman maxim *testis unus, testis nullus* ("one witness is no witness"). Built for HPC-scale longitudinal research, *Pluto* supports checkpointing, job sharding, per-archive rate limiting, and queryable Parquet output.

## Installation

   1. Clone the repository:

      ```bash
      git clone https://github.com/overbrowsing/pluto.git
      cd pluto
      ```

   2. Install Python ([download Python](https://python.org/downloads))

   3. Install required packages:

      ```bash
      pip install -r requirements.txt
      ```

   4. Place your list of URLs in the [input/](input/) folder.

> [!TIP]
> To reproduce [our study](#citing), download the 29.7M URL candidate set from Garg et al.'s *[Not Your Parents' Web](https://archive.org/details/nypw_urls_CDXfirstentry)*:
>
> 1. Download [`nypw_downsampled_deep_firstcdx.gz`](https://archive.org/download/nypw_urls_CDXfirstentry/nypw_downsampled_deep_firstcdx.gz) (1.6 GB) and [`nypw_downsampled_root_firstcdx.gz`](https://archive.org/download/nypw_urls_CDXfirstentry/nypw_downsampled_root_firstcdx.gz) (305.7 MB)
> 2. Place both files in the [input/](input/) folder.
>
> See Garg et al.'s [dataset](https://doi.org/10.1109/JCDL67857.2025.00045) and [methodology](https://arxiv.org/abs/2507.14752) papers for details.

## Usage

   1. Fetch the [web-archive.txt registry](https://github.com/overbrowsing/web-archive.txt#registry):

      ```bash
      python pluto.py fetch-archives
      ```

   2. Run Pluto:

      ```bash
      python pluto.py run

      # Flags

      --candidates <your/path/here>   # use a specific URL file/folder
      --witnesses <ids>               # query specific witnesses, e.g. ia,cc,arq
      --workers <n>                   # concurrent workers
      --shard <i> --num-shards <n>    # split across HPC jobs
      ```

> [!TIP]
> Stopped partway (or it crashed)? Just run the same command again.

   3. Classify:

      ```bash
      python pluto.py classify
      ```

      Classify assigns every URL one of five states (S0-S4):

      | State  | Definition                                                                                          |
      |--------|-----------------------------------------------------------------------------------------------------|
      | **S0** | Resolves on the live web; no content change detected across observations                            |
      | **S1** | Resolves on the live web; content has been edited                                                   |
      | **S2** | Resolves on the live web; content has changed substantially or has been supplanted                  |
      | **S3** | No longer resolves; disappearance corroborated by the configured threshold of independent witnesses |
      | **S4** | No longer resolves; insufficient independent corroboration to confirm disappearance                 |

## Results

Results are written to the [output/](output/) folder as Parquet tables. Each table is append-only: every batch of new evidence lands as its own `part-*.parquet` file, so a run can be stopped and resumed without rewriting anything already on disk.

```
output/
├── parquet/
│   ├── captures/       # one row per archived capture returned by a witness
│   ├── events/         # one row per detected state or content-change event
│   ├── observations/   # one row per live-web query
│   └── urls/           # one row per URL in the study
├── raw/                # cached raw responses, content-addressed by witness
├── .gitkeep
├── checkpoints.db
├── pluto.log
└── summary.parquet     # one row per URL, the classify rollup (the table above)
```

## Credits

Developed by [Overbrowsing](https://overbrowsing.com) at the [Institute for Design Informatics, The University of Edinburgh](https://designinformatics.org).

## Citing

If you use, implement, or reference this project, please cite it as '*Pluto*' and include clear attribution in publications, software, or documentation where appropriate.

A publication related to this project is forthcoming.

## Licenses

*Pluto* is licensed under [Apache 2.0](https://tldrlegal.com/license/apache-license-2-0-apache-2-0). For full licensing details, see the [LICENSE](/LICENSE) file.