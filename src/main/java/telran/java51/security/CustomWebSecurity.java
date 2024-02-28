package telran.java51.security;

import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;
import telran.java51.post.dao.PostRepository;
import telran.java51.post.model.Post;

@Service("customSecurity")
@RequiredArgsConstructor
public class CustomWebSecurity {
	
	final PostRepository postRepository;
	
	public boolean checkPostAuthor(String postId, String userName ) {
		Post post = postRepository.findById(postId).orElse(null);
		return post !=null && userName.equals(post.getAuthor());
	}

}
