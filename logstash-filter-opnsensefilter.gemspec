Gem::Specification.new do |s|
  s.name          = 'logstash-filter-opnsensefilter'
  s.version       = '1.0.2'
  s.licenses      = ['BSD-2-Clause']
  s.summary       = 'Convert CSV output of the filter of OPNsense to reasonable data.'
  s.homepage      = 'https://github.com/fabianfrz'
  s.authors       = ['Fabian Franz']
  s.email         = 'franz.fabian.94@gmail.com'
  s.require_paths = ['lib']

  # Files
  s.files = Dir['lib/**/*','spec/**/*','vendor/**/*','*.gemspec','*.md','CONTRIBUTORS','Gemfile','LICENSE','NOTICE.TXT']
   # Tests
  s.test_files = s.files.grep(%r{^(test|spec|features)/})

  # Special flag to let us know this is actually a logstash plugin
  s.metadata = { "logstash_plugin" => "true", "logstash_group" => "filter" }

  # Gem dependencies
  s.add_runtime_dependency "logstash-core-plugin-api", "~> 2.0"
  s.add_development_dependency 'logstash-devutils'
end
