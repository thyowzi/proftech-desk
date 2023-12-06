package com.douglas.proftechdesk.repositories;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.douglas.proftechdesk.domain.Person;

public interface PersonRepository extends JpaRepository<Person, Integer> {

	boolean existsByCpf(String cpf);

	boolean existsByEmail(String email);

	Optional<Person> findByEmail(String email);
}