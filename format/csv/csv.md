### TSV to CSV

```sh
$ fq -d csv -o comma="\t" to_csv file.tsv
```

### Convert rows to objects based on header row

```sh
$ fq -d csv '.[0] as $t | .[1:] | map(with_entries(.key = $t[.key]))' file.csv
```

### Identifiers
- [Q935809](http://www.wikidata.org/entity/Q935809)
- [x-fmt/18](https://www.nationalarchives.gov.uk/PRONOM/x-fmt/18)
