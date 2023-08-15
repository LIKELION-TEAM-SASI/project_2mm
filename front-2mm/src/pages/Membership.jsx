import { useNavigate } from "react-router-dom";
import React, { useState } from "react";
import styled from "styled-components";
import axios from "axios";

const Container = styled.div`
  position: relative;
  margin: 30px 0;
  max-width: 375px;
  height: 740px;
  background: white;
  border: 1px solid gray;
  margin: 30px auto;

  @media screen and (max-width: 768px) {
    width: 100%;
    padding-left: 0rem;
    padding-right: 0rem;
  }
`;

const Back = styled.div`
  position: relative;
  margin-top: 17px;
  margin-left: 15px;
`;

const Title = styled.div`
  position: relative;
  top: -23px;
  left: 150px;
`;

const SubTitle = styled.div`
  position: relative;
  top: 25px;
  left: 25px;
`;

const InputName = styled.input`
  position: relative;
  width: 300px;
  height: 50px;
  left: 22px;
  top: 55px;
  border-radius: 7px;
  border: 1.5px solid #0085ff;
  font-size: 20px;
  padding-left: 15px;

  ::placeholder {
    color: #7c7c7c;
  }
`;

const NextBtn = styled.div`
  position: relative;
  top: 470px;
  left: 22px;
`;

const Membership = () => {
  const navigate = useNavigate();

  const [inputs, setInputs] = useState({
    username: "",
  });

  const { username } = inputs;
  const onChange = (e) => {
    const { value, name } = e.target;
    setInputs({
      ...inputs,
      [name]: value,
    });
  };

  const onSubmit = async () => {
    try {
      // HTTP POST 요청으로 새로운 게시물 생성
      const response = await axios.post("http://127.0.0.1:8000/signup/", {
        username: inputs.username,
      });

      const token = response.data.token;
      localStorage.setItem("token", token);

      console.log(token);

      navigate("/Membership2");
    } catch (error) {
      // 에러 발생 시 에러 처리
      console.error("Error creating new post:", error);
    }
  };

  return (
    <Container>
      <Back>&nbsp;</Back>
      <Title>
        <img
          src={`${process.env.PUBLIC_URL}/images/title_text.svg`}
          alt="title"
        />
      </Title>
      <SubTitle>
        <img
          src={`${process.env.PUBLIC_URL}/images/subtitle_text.svg`}
          alt="subtitle"
        />
      </SubTitle>
      <InputName
        placeholder="홍길동"
        name="username"
        value={username}
        onChange={onChange}
      ></InputName>
      <NextBtn onClick={onSubmit}>
        <img src={`${process.env.PUBLIC_URL}/images/next_btn.svg`} alt="btn" />
      </NextBtn>
    </Container>
  );
};

export default Membership;
