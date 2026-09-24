# Pluto ♇

## Overview

*Pluto* is a research tool for reconstructing web URL histories. It supports research into URL lifespan, link rot, content change, and web persistence by querying supported web archives listed in our [web-archive.txt registry](https://github.com/overbrowsing/web-archive.txt#registry) and the live web. Findings are corroborated across archives rather than relying on a single source, following the Roman maxim testis unus, *testis unus, testis nullus* (one witness is no witness). Built for HPC-scale longitudinal research, *Pluto* supports checkpointing, job sharding, per-archive rate limiting, and queryable Parquet output.

## Installation

   1. Clone the repository:

      ```bash
      git clone https://github.com/overbrowsing/pluto.git
      cd pluto
      ```

   2. Install Python ([download Python](https://python.org/downloads))

   3. Install dependencies:

      ```bash
      pip install -r requirements.txt
      ```

## Usage

   1. Fetch the [web-archive.txt registry](https://github.com/overbrowsing/web-archive.txt#registry):

      ```bash
      python pluto.py fetch-archives
      ```

   2. Run Pluto:

      ```bash
      python pluto.py run

      # Flags

      --input <path|domain>           # URL list file/folder or URL; default: input/, e.g. path/to/folder/ or example.com
      --output <path>                 # output directory; default: output/, e.g. path/to/folder/
      --scope <root|hosts|deep|all>   # what to discover for a domain, or filter for a file/folder; default: all = root+hosts+deep
      --changes                       # fetch full capture histories to detect content changes by digest; default: first and last capture only
      --witnesses <ids>               # web archives to query (default: all), e.g. live_web,ia,arq
      --min-witnesses <n>             # witnesses needed to stop early (default: 2; off with --changes unless set explicitly)
      --retry                         # re-attempt witnesses that failed for good last run; pair with --witnesses to retry just one, e.g. --witnesses live_web --retry
      --workers <n>                   # concurrent workers, e.g. 30
      --shard <i>/<n>                 # HPC job shard, e.g. 2/8
      ```

> [!TIP]
> Stopped partway, or did it crash? Just run the same command again to pick up where you left off.

   3. Classify:

      ```bash
      python pluto.py classify
      ```

      Classify assigns every URL one of five states (S0-S4):

      | State  | Definition                                                                                       |
      |--------|--------------------------------------------------------------------------------------------------|
      | **S0** | Resolves on the live web; no content change detected, or too few observations to test for change |
      | **S1** | Resolves; content has changed, but size is comparable                                            |
      | **S2** | Resolves; content has changed and size differs by more than half, consistent with replacement    |
      | **S3** | Does not resolve; at least two witnesses (the default threshold) report it inaccessible          |
      | **S4** | Does not resolve; too few witnesses report it inaccessible to confirm disappearance              |

## Results

Results are written as Parquet tables. Each batch is saved as a separate `part-*.parquet` file, so runs can be stopped and resumed without rewriting existing data.

```
output/
├── parquet/
│   ├── captures/       # one row per archived capture returned by a witness
│   ├── events/         # one row per detected state or content-change event
│   ├── observations/   # one row per live-web query
│   └── urls/           # one row per URL in the study
├── raw/                # cached raw responses, packed into gzip JSONL segments per witness
├── .gitkeep
├── checkpoints.db
├── pluto.log
└── summary.parquet     # one row per URL, the classify rollup (the table above)
```

## Credits

Developed by [Overbrowsing](https://overbrowsing.com) at the [Institute for Design Informatics, The University of Edinburgh](https://designinformatics.org).

## Citing

If you use, implement, or reference this project, please cite it as '*Pluto*' and include clear attribution in publications, software, or documentation where appropriate.

## Licenses

*Pluto* is licensed under [Apache 2.0](https://tldrlegal.com/license/apache-license-2-0-apache-2-0). For full licensing details, see the [LICENSE](/LICENSE) file.