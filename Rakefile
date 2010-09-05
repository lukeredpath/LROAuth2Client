require 'rake/tasklib'

TARGET_NAME = "LROAuth2Client"

module XcodeBuild
  class BuildTask < Rake::TaskLib
    attr_accessor :target, :configuration, :sdk
    
    def initialize(name)
      @name = name
      @configuration = "Debug"
      yield self if block_given?
      define
    end
    
    def define
      raise "Xcode build target must be defined (in task: #{@name})" if target.nil?
      
      desc "Build the #{target} target in #{configuration}"
      task @name do
        system("xcodebuild -target #{target} -configuration #{configuration} build -sdk #{sdk}")
      end
    end
  end
  
  def self.clean!
    system("xcodebuild clean")
  end
end

def xcodebuild(name, &block)
  XcodeBuild::BuildTask.new(name, &block)
end

SDK_VERSION = ENV['SDK'] || '4.0'

namespace :build do
  xcodebuild :device do |t|
    t.target        = "#{TARGET_NAME}-Device"
    t.configuration = "Release"
    t.sdk           = "iphoneos#{SDK_VERSION}"
  end

  xcodebuild :simulator do |t|
    t.target        = "#{TARGET_NAME}-Simulator"
    t.configuration = "Release"
    t.sdk           = "iphonesimulator#{SDK_VERSION}"
  end
  
  desc "Build the combined static library"
  task :combined => [:device, :simulator] do
    ENV["BUILD_DIR"] = "build"
    ENV["BUILD_STYLE"] = "Release"
    
    if system("sh Scripts/CombineLibs.sh")
      puts "Combined libraries built successfully."
    else
      puts "There was an error building the combined libraries."
    end
  end
  
  desc "Package up the framework for release"
  task :framework => [:clean, :combined] do
    if system("sh Scripts/iPhoneFramework.sh")
      puts "Framework built successfully."
    else
      puts "There was an error building the framework."
    end
  end
end

desc "Clean the build directory"
task :clean do
  XcodeBuild.clean!
end

task :default => "build:framework"
